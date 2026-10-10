package technitium

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Record is one resource record as the server holds it.
type Record struct {
	// Name is the record's full domain name, the zone's own for a record
	// at its apex
	Name     string `json:"name"`
	Type     string `json:"type"`
	TTL      int    `json:"ttl"`
	Disabled bool   `json:"disabled"`
	Comments string `json:"comments"`
	// Data is the record's data, whose fields depend on its type: ipAddress
	// for an A, cname for a CNAME, preference and exchange for an MX
	Data RData `json:"rData"`
	// LastUsedOn is when the record last answered a query, in UTC; a record
	// never used carries the zero time, which Used reports as never
	LastUsedOn   string `json:"lastUsedOn"`
	LastModified string `json:"lastModified"`
	// ExpiryTTL is how many seconds after it was last changed the server
	// deletes the record by itself, 0 for never
	ExpiryTTL int `json:"expiryTtl"`
	// GlueRecords are the addresses an NS record carries for its name
	// server, which the server gives beside the record's data rather than in
	// it
	GlueRecords []string `json:"glueRecords"`
}

// RData is a record's data as the API gives it, by field name.
type RData map[string]any

// field is one field of the data as text, "" when it is not there. A list is
// written with commas between its entries, and a table of parameters, as an
// SVCB record's, as key=value pairs in the order of their keys.
func (d RData) field(name string) string {
	switch v := d[name].(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case int:
		return strconv.Itoa(v)
	case bool:
		return strconv.FormatBool(v)
	case []string:
		return strings.Join(v, ",")
	case []any:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			parts = append(parts, fmt.Sprint(item))
		}

		return strings.Join(parts, ",")
	case map[string]any:
		parts := make([]string, 0, len(v))
		for _, key := range slices.Sorted(maps.Keys(v)) {
			parts = append(parts, fmt.Sprintf("%s=%v", key, v[key]))
		}

		return strings.Join(parts, " ")
	default:
		return ""
	}
}

// dataField is one field of a record's data: what the server gives it back
// under, and what the calls that write a record take it as.
type dataField struct {
	// name is the field in a record's data as it is read, and param the
	// parameter it is sent as: the same word for most types
	name, param string
	// fresh is the parameter an update takes the field's new value in. One
	// that is param again is the whole of a record that is the only one at
	// its name, a CNAME's target: an update takes the new one there and no
	// old one. "" is a field an update cannot change, which is sent as it is
	fresh string
	// option fields are no part of which record is meant: they are sent
	// when a record is added and when it is changed, where one left out is
	// reset, and never to say which record to delete. They may be left out
	option bool
	// empty fields may be given as nothing, as a NAPTR's regular expression
	// is as often as not
	empty bool
}

// layouts are the fields of each record type's data, in the order a zone
// file writes them, with the options after. A type not here is one the
// server has no layout of its own for, which it takes and gives as bytes in
// hex (see unknownLayout).
var layouts = map[string][]dataField{
	"A":     {{name: "ipAddress", param: "ipAddress", fresh: "newIpAddress"}},
	"AAAA":  {{name: "ipAddress", param: "ipAddress", fresh: "newIpAddress"}},
	"NS":    {{name: "nameServer", param: "nameServer", fresh: "newNameServer"}, {name: "glue", param: "glue", fresh: "glue", option: true}},
	"CNAME": {{name: "cname", param: "cname", fresh: "cname"}},
	"PTR":   {{name: "ptrName", param: "ptrName", fresh: "newPtrName"}},
	"MX":    {{name: "preference", param: "preference", fresh: "newPreference"}, {name: "exchange", param: "exchange", fresh: "newExchange"}},
	"TXT":   {{name: "text", param: "text", fresh: "newText"}, {name: "splitText", param: "splitText", fresh: "newSplitText", option: true}},
	"RP":    {{name: "mailbox", param: "mailbox", fresh: "newMailbox"}, {name: "txtDomain", param: "txtDomain", fresh: "newTxtDomain"}},
	"SRV":   {{name: "priority", param: "priority", fresh: "newPriority"}, {name: "weight", param: "weight", fresh: "newWeight"}, {name: "port", param: "port", fresh: "newPort"}, {name: "target", param: "target", fresh: "newTarget"}},
	"NAPTR": {{name: "order", param: "naptrOrder", fresh: "naptrNewOrder"}, {name: "preference", param: "naptrPreference", fresh: "naptrNewPreference"}, {name: "flags", param: "naptrFlags", fresh: "naptrNewFlags", empty: true}, {name: "services", param: "naptrServices", fresh: "naptrNewServices", empty: true}, {name: "regexp", param: "naptrRegexp", fresh: "naptrNewRegexp", empty: true}, {name: "replacement", param: "naptrReplacement", fresh: "naptrNewReplacement", empty: true}},
	"DNAME": {{name: "dname", param: "dname", fresh: "dname"}},
	"DS":    {{name: "keyTag", param: "keyTag", fresh: "newKeyTag"}, {name: "algorithm", param: "algorithm", fresh: "newAlgorithm"}, {name: "digestType", param: "digestType", fresh: "newDigestType"}, {name: "digest", param: "digest", fresh: "newDigest"}},
	"SSHFP": {{name: "algorithm", param: "sshfpAlgorithm", fresh: "newSshfpAlgorithm"}, {name: "fingerprintType", param: "sshfpFingerprintType", fresh: "newSshfpFingerprintType"}, {name: "fingerprint", param: "sshfpFingerprint", fresh: "newSshfpFingerprint"}},
	"TLSA":  {{name: "certificateUsage", param: "tlsaCertificateUsage", fresh: "newTlsaCertificateUsage"}, {name: "selector", param: "tlsaSelector", fresh: "newTlsaSelector"}, {name: "matchingType", param: "tlsaMatchingType", fresh: "newTlsaMatchingType"}, {name: "certificateAssociationData", param: "tlsaCertificateAssociationData", fresh: "newTlsaCertificateAssociationData"}},
	"SVCB":  svcLayout,
	"HTTPS": svcLayout,
	"URI":   {{name: "priority", param: "uriPriority", fresh: "newUriPriority"}, {name: "weight", param: "uriWeight", fresh: "newUriWeight"}, {name: "uri", param: "uri", fresh: "newUri"}},
	"CAA":   {{name: "flags", param: "flags", fresh: "newFlags"}, {name: "tag", param: "tag", fresh: "newTag"}, {name: "value", param: "value", fresh: "newValue"}},
	"ANAME": {{name: "aname", param: "aname", fresh: "newAName"}},
	"FWD":   {{name: "protocol", param: "protocol", fresh: "newProtocol"}, {name: "forwarder", param: "forwarder", fresh: "newForwarder"}, {name: "priority", param: "forwarderPriority", fresh: "forwarderPriority", option: true}, {name: "dnssecValidation", param: "dnssecValidation", fresh: "dnssecValidation", option: true}, {name: "proxyType", param: "proxyType", fresh: "proxyType", option: true}, {name: "proxyAddress", param: "proxyAddress", fresh: "proxyAddress", option: true}, {name: "proxyPort", param: "proxyPort", fresh: "proxyPort", option: true}, {name: "proxyUsername", param: "proxyUsername", fresh: "proxyUsername", option: true}, {name: "proxyPassword", param: "proxyPassword", fresh: "proxyPassword", option: true}},
	"APP":   {{name: "appName", param: "appName"}, {name: "classPath", param: "classPath"}, {name: "data", param: "recordData", fresh: "recordData", option: true}},
}

// svcLayout is an SVCB record's data, and an HTTPS record's, which is one
// by another name. Its parameters are a table the calls take with bars
// between every key and value, and "false" for none.
var svcLayout = []dataField{{name: "svcPriority", param: "svcPriority", fresh: "newSvcPriority"}, {name: "svcTargetName", param: "svcTargetName", fresh: "newSvcTargetName"}, {name: "svcParams", param: "svcParams", fresh: "newSvcParams", empty: true}, {name: "autoIpv4Hint", param: "autoIpv4Hint", fresh: "autoIpv4Hint", option: true}, {name: "autoIpv6Hint", param: "autoIpv6Hint", fresh: "autoIpv6Hint", option: true}}

// unknownLayout is the data of a type the server has no layout for - a LOC,
// an HINFO, a NULL - which it takes and gives as bytes written in hex with
// colons between, 01:02:03.
var unknownLayout = []dataField{{name: "value", param: "rdata", fresh: "newRData"}}

// soaFields are an SOA record's fields in the order a zone file writes
// them.
var soaFields = []string{"primaryNameServer", "responsiblePerson", "serial", "refresh", "retry", "expire", "minimum"}

// fixedTypes are the types that are not written as a record is: a zone's
// SOA is changed with UpdateSOA and never added or deleted, and the DNSSEC
// types are the server's own to make when it signs a zone.
var fixedTypes = []string{"SOA", "DNSKEY", "RRSIG", "NSEC", "NSEC3", "NSEC3PARAM", "ZONEMD"}

// layoutOf is the fields of a record type's data.
func layoutOf(recordType string) []dataField {
	if layout, ok := layouts[recordType]; ok {
		return layout
	}

	return unknownLayout
}

// sent is a field of a record's data as a call takes it: an SVCB record's
// parameters with bars between every key and value where they are read
// with an equals sign and a space, its target as a dot where the server
// reads the root back as nothing, and glue from the record itself.
func (d RData) sent(recordType string, f dataField) string {
	// a field may be given under the name it is read as or the one it is sent as
	value := d.field(f.name)
	if value == "" {
		value = d.field(f.param)
	}
	switch {
	case f.name == "svcParams":
		table, isTable := d[f.name].(map[string]any)
		if !isTable {
			table = map[string]any{}
			for pair := range strings.FieldsSeq(value) {
				key, val, _ := strings.Cut(pair, "=")
				table[key] = val
			}
		}
		parts := make([]string, 0, 2*len(table))
		for _, key := range slices.Sorted(maps.Keys(table)) {
			parts = append(parts, key, fmt.Sprint(table[key]))
		}
		if len(parts) == 0 {
			return "false"
		}

		return strings.Join(parts, "|")
	case f.name == "svcTargetName" && value == "":
		return "."
	case recordType == "TXT" && f.name == "splitText" && value == "false":
		return ""
	default:
		return value
	}
}

// targetField is the field holding the domain name a record points at, for
// the types that point at one.
var targetField = map[string]string{
	"NS":    "nameServer",
	"CNAME": "cname",
	"PTR":   "ptrName",
	"MX":    "exchange",
	"SRV":   "target",
	"DNAME": "dname",
	"ANAME": "aname",
}

// Value is the record's data on one line, as a zone file would write it:
// 10.0.0.4 for an A, "10 mail.example.com" for an MX, "1 . alpn=h2,h3" for
// an HTTPS. What is an option of the record and no part of its value - an
// NS record's glue, how a forwarder is reached - is not in it. A NAPTR's
// flags, services and expression are each in quotes, since any of them may
// be nothing.
func (r *Record) Value() string {
	if r.Type == "SOA" {
		parts := make([]string, 0, len(soaFields))
		for _, name := range soaFields {
			parts = append(parts, r.Data.field(name))
		}

		return strings.Join(parts, " ")
	}
	layout, known := layouts[r.Type]
	if !known && r.Data.field("value") != "" && len(r.Data) == 1 {
		return r.Data.field("value")
	}
	if !known {
		// a type read and never written, an SOA or a signature: every field by name, so nothing is left out
		names := slices.Sorted(maps.Keys(r.Data))
		parts := make([]string, 0, len(names))
		for _, name := range names {
			parts = append(parts, fmt.Sprintf("%s=%v", name, r.Data[name]))
		}

		return strings.Join(parts, " ")
	}

	parts := make([]string, 0, len(layout))
	for _, f := range layout {
		value := r.Data.field(f.name)
		switch {
		case f.option:
			continue
		case r.Type == "NAPTR" && f.empty && f.name != "replacement":
			value = strconv.Quote(value)
		case f.name == "svcTargetName" && value == "", f.name == "replacement" && value == "":
			value = "."
		case f.name == "svcParams" && value == "":
			continue
		default:
		}
		parts = append(parts, value)
	}

	return strings.Join(parts, " ")
}

// OptionNames are what a record of a type may have beside its value, by the
// names the API takes them under: glue for an NS, how a forwarder is reached
// for a FWD, what an APP record tells its app.
func OptionNames(recordType string) []string {
	var names []string
	for _, f := range layoutOf(recordType) {
		if f.option {
			names = append(names, f.param)
		}
	}

	return names
}

// Options are the record's options that are set, by the names the API takes
// them under. A proxy's password is not among them: the server never gives
// one back.
func (r *Record) Options() map[string]string {
	out := map[string]string{}
	for _, f := range layoutOf(r.Type) {
		if !f.option {
			continue
		}
		value := r.Data.field(f.name)
		if f.name == "glue" && value == "" {
			value = strings.Join(r.GlueRecords, ",")
		}
		if value != "" {
			out[f.param] = value
		}
	}

	return out
}

// SetOption sets one option of a record's data, by the name the API takes
// it under: a type that has no such option is refused.
func SetOption(data RData, recordType, option, value string) error {
	for _, f := range layoutOf(recordType) {
		if f.option && f.param == option {
			delete(data, f.param)
			data[f.name] = value

			return nil
		}
	}
	if names := OptionNames(recordType); len(names) > 0 {
		return fmt.Errorf("a %s record has no option named %s: it has %s", recordType, option, strings.Join(names, ", "))
	}

	return fmt.Errorf("a %s record has no options beside its value", recordType)
}

// Target is the domain name the record points at - a CNAME's, an MX's
// exchange, an NS's server - and "" for a type that points at none.
func (r *Record) Target() string {
	return r.Data.field(targetField[r.Type])
}

// Address is the address of an A or an AAAA record.
func (r *Record) Address() (netip.Addr, bool) {
	if r.Type != "A" && r.Type != "AAAA" {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(r.Data.field("ipAddress"))

	return addr, err == nil
}

// SOA is what a zone's SOA record says of the zone.
type SOA struct {
	// Primary is the name server the zone names as its primary, and
	// Responsible the mailbox of whoever runs it
	Primary, Responsible string
	Serial               uint32
	// Refresh, Retry and Expire are a copy's times, and Minimum how long
	// the answer that a name does not exist may be kept: all in seconds
	Refresh, Retry, Expire, Minimum int
	// SerialByDate is the zone numbering its changes by the day,
	// 2026101001, where the default counts up from 1
	SerialByDate bool
}

// SOA reads an SOA record; any other record gives an empty one.
func (r *Record) SOA() SOA {
	if r.Type != "SOA" {
		return SOA{}
	}
	number := func(field string) int {
		n, _ := strconv.Atoi(r.Data.field(field))

		return n
	}

	return SOA{Primary: r.Data.field("primaryNameServer"), Responsible: r.Data.field("responsiblePerson"), Serial: uint32(number("serial")), Refresh: number("refresh"), Retry: number("retry"), Expire: number("expire"), Minimum: number("minimum"), SerialByDate: r.Data.field("useSerialDateScheme") == yes} //nolint:gosec // G115: a serial is 32 bits wide by definition
}

// Used is when the record last answered a query, and false for one that
// never has.
func (r *Record) Used() (time.Time, bool) {
	return ParseTime(r.LastUsedOn)
}

// Modified is when the record was last changed, and false when the server
// does not say.
func (r *Record) Modified() (time.Time, bool) {
	return ParseTime(r.LastModified)
}

// ZoneRecords is a zone and records in it.
type ZoneRecords struct {
	Zone    Zone     `json:"zone"`
	Records []Record `json:"records"`
}

// ZoneRecords reads every record in a zone.
func (c *Client) ZoneRecords(ctx context.Context, zone string) (*ZoneRecords, error) {
	if zone == "" {
		return nil, errors.New("zones/records/get: which zone")
	}

	var out ZoneRecords
	if err := c.read(ctx, "zones/records/get", url.Values{"domain": {zone}, "zone": {zone}, "listZone": {yes}}, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// RecordsAt reads the records at one domain name, in the zone named or, with
// none named, in the closest zone the server holds for it.
func (c *Client) RecordsAt(ctx context.Context, name, zone string) (*ZoneRecords, error) {
	if name == "" {
		return nil, errors.New("zones/records/get: which name")
	}
	params := url.Values{"domain": {name}}
	if zone != "" {
		params.Set("zone", zone)
	}

	var out ZoneRecords
	if err := c.read(ctx, "zones/records/get", params, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// NewRecord is a record to add.
type NewRecord struct {
	// Zone is the zone to add to; "" is the closest the server holds for
	// the name
	Zone string
	Name string
	Type string
	// TTL in seconds; 0 is the server's default for the type
	TTL      int
	Comments string
	// Data is the record's data by field, as a Record carries it
	Data RData
	// Overwrite replaces every record of this type at the name with this
	// one, where the default adds beside them
	Overwrite bool
	// ExpiryTTL is how many seconds after it was last changed the server
	// deletes the record by itself; 0 is never
	ExpiryTTL int
	// PTR has the server add the PTR record for an A or an AAAA record's
	// address as well, in the reverse zone it holds for it; with none it
	// refuses, unless CreatePTRZone has it make the reverse zone too
	PTR, CreatePTRZone bool
	// UpdateSVCBHints has the server bring the address hints of the zone's
	// SVCB and HTTPS records that name this A or AAAA record's name, and are
	// set to keep their hints themselves, up to date with it
	UpdateSVCBHints bool
}

// AddRecord adds a record to a zone and returns it as the server now holds
// it.
func (c *Client) AddRecord(ctx context.Context, rec NewRecord) (*Record, error) {
	if rec.Name == "" || rec.Type == "" {
		return nil, errors.New("zones/records/add: a record needs a name and a type")
	}
	params, err := addParams("zones/records/add", rec.Type, rec.Data)
	if err != nil {
		return nil, err
	}
	params.Set("domain", rec.Name)
	params.Set("type", rec.Type)
	if rec.Zone != "" {
		params.Set("zone", rec.Zone)
	}
	if rec.TTL > 0 {
		params.Set("ttl", strconv.Itoa(rec.TTL))
	}
	if rec.Comments != "" {
		params.Set("comments", rec.Comments)
	}
	if rec.ExpiryTTL > 0 {
		params.Set("expiryTtl", strconv.Itoa(rec.ExpiryTTL))
	}
	for param, on := range map[string]bool{"overwrite": rec.Overwrite, "ptr": rec.PTR, "createPtrZone": rec.CreatePTRZone, "updateSvcbHints": rec.UpdateSVCBHints} {
		if on {
			params.Set(param, yes)
		}
	}

	var out struct {
		AddedRecord Record `json:"addedRecord"`
	}
	if err := c.write(ctx, "zones/records/add", params, &out); err != nil {
		return nil, err
	}

	return &out.AddedRecord, nil
}

// DeleteRecord deletes one record from a zone: the one at the name with the
// type and the data given. zone "" is the closest the server holds for the
// name.
func (c *Client) DeleteRecord(ctx context.Context, zone string, rec *Record) error {
	return c.removeRecord(ctx, zone, rec, false)
}

// DeleteAddress is DeleteRecord for an A or an AAAA record, which also has
// the server bring the address hints of the zone's SVCB and HTTPS records
// that name the record's name, and are set to keep their hints themselves,
// up to date with the address gone.
func (c *Client) DeleteAddress(ctx context.Context, zone string, rec *Record) error {
	if rec.Type != "A" && rec.Type != "AAAA" {
		return errors.New("zones/records/delete: only an A or an AAAA record is an address for a hint to follow")
	}

	return c.removeRecord(ctx, zone, rec, true)
}

func (c *Client) removeRecord(ctx context.Context, zone string, rec *Record, hints bool) error {
	if rec.Name == "" || rec.Type == "" {
		return errors.New("zones/records/delete: which record: it needs a name and a type")
	}
	params, err := whichParams("zones/records/delete", rec.Type, rec.Data)
	if err != nil {
		return err
	}
	params.Set("domain", rec.Name)
	params.Set("type", rec.Type)
	if zone != "" {
		params.Set("zone", zone)
	}
	if hints {
		params.Set("updateSvcbHints", yes)
	}

	return c.write(ctx, "zones/records/delete", params, nil)
}

// writable refuses the types that are not written as a record is.
func writable(path, recordType string) error {
	if slices.Contains(fixedTypes, recordType) {
		return fmt.Errorf("%s: a %s record is not added, changed or deleted as other records are: a zone has its SOA from the start, which is changed where it stands, and what DNSSEC adds to a zone is the server's own to make", path, recordType)
	}

	return nil
}

// needs is a type's fields as a message names them: the ones a record
// cannot be without.
func needs(recordType string) string {
	var names []string
	for _, f := range layoutOf(recordType) {
		if !f.option {
			names = append(names, f.name)
		}
	}

	return strings.Join(names, ", ")
}

// addParams is a record's data as the parameters it is added with. Every
// field the type needs must be there: sent without one, the server would
// answer with an error about a parameter rather than about the record.
func addParams(path, recordType string, data RData) (url.Values, error) {
	if err := writable(path, recordType); err != nil {
		return nil, err
	}

	params := url.Values{}
	// a TXT record given as its strings in base64 is taken as those, exactly, and its text is not sent beside them
	if strings64 := data.field("characterStringsBase64"); recordType == "TXT" && strings64 != "" && data.field("text") == "" {
		params.Set("characterStringsBase64", strings64)

		return params, nil
	}
	for _, f := range layoutOf(recordType) {
		value := data.sent(recordType, f)
		switch {
		case value != "":
			params.Set(f.param, value)
		case f.option:
		case f.empty:
			params.Set(f.param, "")
		default:
			return nil, fmt.Errorf("%s: record type %s needs %s, and %s is not given", path, recordType, needs(recordType), f.name)
		}
	}

	return params, nil
}

// whichParams are the parameters that say which record is meant, to delete
// it or to change it: its data without its options. A record that is the
// only one of its type at its name, a CNAME, is meant by its name and type
// alone, and the API takes no value for it. A TXT record read from the
// server is named by its strings exactly, in base64, since its text alone
// does not say where one string ends and the next begins.
func whichParams(path, recordType string, data RData) (url.Values, error) {
	if err := writable(path, recordType); err != nil {
		return nil, err
	}

	params := url.Values{}
	if strings64 := data.field("characterStringsBase64"); recordType == "TXT" && strings64 != "" {
		params.Set("characterStringsBase64", strings64)

		return params, nil
	}
	for _, f := range layoutOf(recordType) {
		if f.fresh == f.param || (f.option && recordType != "TXT") || (f.fresh == "" && path == "zones/records/delete") {
			continue
		}
		value := data.sent(recordType, f)
		switch {
		case value != "":
			params.Set(f.param, value)
		case f.option:
		case f.empty:
			params.Set(f.param, "")
		default:
			return nil, fmt.Errorf("%s: record type %s needs %s, and %s is not given", path, recordType, needs(recordType), f.name)
		}
	}

	return params, nil
}

// RecordUpdate is a record as it should be once changed. Every field is
// what the record will have: the server keeps nothing an update does not
// send, so a TTL, a comment or a disabled state left out of one is reset,
// not kept. Fill it from the record as it is (UpdateOf) and change what is
// to change.
type RecordUpdate struct {
	// Name is the record's name; a different one moves it there
	Name     string
	TTL      int
	Disabled bool
	Comments string
	// ExpiryTTL is how many seconds after this change the server deletes
	// the record by itself; 0 is never
	ExpiryTTL int
	// Data is the record's data by field, as a Record carries it, its
	// options among them: what a forwarder record is reached through, an NS
	// record's glue. An option left out is reset by the server
	Data RData
	// PTR has the server change the PTR record for an A or an AAAA record's
	// address with it, CreatePTRZone make the reverse zone when it holds
	// none, and UpdateSVCBHints bring the hints of the zone's SVCB and
	// HTTPS records up to date
	PTR, CreatePTRZone, UpdateSVCBHints bool
}

// UpdateOf is a record as it is, to change and hand to UpdateRecord: its
// data with its options, and an NS record's glue with them. What the server
// never gives back cannot be carried over: a forwarder record that goes
// through a proxy with a password must be given the password again.
func UpdateOf(rec *Record) RecordUpdate {
	data := maps.Clone(rec.Data)
	if data == nil {
		data = RData{}
	}
	if rec.Type == "NS" && len(rec.GlueRecords) > 0 {
		data["glue"] = strings.Join(rec.GlueRecords, ",")
	}

	return RecordUpdate{Name: rec.Name, TTL: rec.TTL, Disabled: rec.Disabled, Comments: rec.Comments, ExpiryTTL: rec.ExpiryTTL, Data: data}
}

// UpdateRecord changes one record in place - its data, its name, its TTL,
// its comment, whether it is disabled - and returns it as the server now
// holds it. current says which record: its name, type and data as they are.
// zone "" is the closest the server holds for the name.
//
// A record the server does not hold is refused with an error about the zone,
// in the server's words: it is the record that is not there.
func (c *Client) UpdateRecord(ctx context.Context, zone string, current *Record, want RecordUpdate) (*Record, error) {
	if current.Name == "" || current.Type == "" {
		return nil, errors.New("zones/records/update: which record: it needs a name and a type")
	}
	params, err := whichParams("zones/records/update", current.Type, current.Data)
	if err != nil {
		return nil, err
	}
	// what the record is to say, each field in the parameter an update takes it in; a field an update cannot change stays as it was sent above
	if strings64 := want.Data.field("characterStringsBase64"); current.Type == "TXT" && strings64 != "" && (want.Data.field("text") == "" || want.Data.field("text") == current.Data.field("text")) {
		params.Set("newCharacterStringsBase64", strings64)
	} else {
		for _, f := range layoutOf(current.Type) {
			value := want.Data.sent(current.Type, f)
			switch {
			case f.fresh == "":
			case value != "":
				params.Set(f.fresh, value)
			case f.option:
			case f.empty:
				params.Set(f.fresh, "")
			default:
				return nil, fmt.Errorf("zones/records/update: record type %s needs %s, and %s is not given", current.Type, needs(current.Type), f.name)
			}
		}
	}
	for param, on := range map[string]bool{"ptr": want.PTR, "createPtrZone": want.CreatePTRZone, "updateSvcbHints": want.UpdateSVCBHints} {
		if on {
			params.Set(param, yes)
		}
	}
	params.Set("domain", current.Name)
	params.Set("type", current.Type)
	if zone != "" {
		params.Set("zone", zone)
	}
	if want.Name != "" && !strings.EqualFold(want.Name, current.Name) {
		params.Set("newDomain", want.Name)
	}
	// everything the record is to keep is sent: what is left out is reset
	params.Set("ttl", strconv.Itoa(want.TTL))
	params.Set("disable", strconv.FormatBool(want.Disabled))
	params.Set("comments", want.Comments)
	params.Set("expiryTtl", strconv.Itoa(want.ExpiryTTL))

	var out struct {
		UpdatedRecord Record `json:"updatedRecord"`
	}
	if err := c.write(ctx, "zones/records/update", params, &out); err != nil {
		return nil, err
	}

	return &out.UpdatedRecord, nil
}

// WritableTypes are the record types the server has a layout of its own
// for, which this client adds, changes and deletes by their fields. Any
// other type but the ones a server keeps for itself is written too, as
// bytes in hex.
func WritableTypes() []string {
	return slices.Sorted(maps.Keys(layouts))
}

// words splits a value on its spaces, keeping what is in double quotes
// together and the quotes out of it: 100 10 "S" "SIP+D2U" "" . is six.
func words(value string) []string {
	var out []string
	var word strings.Builder
	quoted, begun := false, false
	for _, r := range value {
		switch {
		case r == '"':
			quoted, begun = !quoted, true
		case (r == ' ' || r == '\t') && !quoted:
			if begun {
				out = append(out, word.String())
			}
			word.Reset()
			begun = false
		default:
			word.WriteRune(r)
			begun = true
		}
	}
	if begun {
		out = append(out, word.String())
	}

	return out
}

// ParseValue reads a record's data from its value on one line, as Value
// writes one: an address for an A, "10 mail.example.com" for an MX,
// "1 . alpn=h2,h3 port=443" for an HTTPS. A TXT record's value is its whole
// text, spaces and all; an APP record's is the app's name, which may hold
// spaces, and then its class; a type the server has no layout for is its
// bytes in hex, 01:02:03. The options of a record are no part of its value.
func ParseValue(recordType, value string) (RData, error) {
	if err := writable("a record", recordType); err != nil {
		return nil, err
	}
	var fields []string
	for _, f := range layoutOf(recordType) {
		if !f.option {
			fields = append(fields, f.name)
		}
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("a %s record's value is %s, and none was given", recordType, strings.Join(fields, " "))
	}

	parts := words(value)
	switch recordType {
	case "TXT":
		return RData{"text": value}, nil
	case "APP":
		// the class is the last word and the app's name everything before it
		if len(parts) < 2 {
			return nil, fmt.Errorf("an APP record's value is the app's name and then the class of the part that answers, and %q is one word", value)
		}

		return RData{"appName": strings.Join(parts[:len(parts)-1], " "), "classPath": parts[len(parts)-1]}, nil
	case "SVCB", "HTTPS":
		if len(parts) < 2 {
			return nil, fmt.Errorf("a %s record's value is its priority, its target and then its parameters as key=value, and %q is %d of those", recordType, value, len(parts))
		}
		table := map[string]any{}
		for _, pair := range parts[2:] {
			key, val, _ := strings.Cut(pair, "=")
			table[key] = val
		}

		return RData{"svcPriority": parts[0], "svcTargetName": parts[1], "svcParams": table}, nil
	default:
	}
	if _, known := layouts[recordType]; !known && len(parts) != 1 {
		return nil, fmt.Errorf("the server has no layout for a %s record, and takes one as its bytes in hex with colons between, as 01:02:03: %q is %d words", recordType, value, len(parts))
	}
	if len(parts) < len(fields) {
		return nil, fmt.Errorf("a %s record's value is %s, and %q is %d of those", recordType, strings.Join(fields, " "), value, len(parts))
	}
	if len(fields) == 1 && len(parts) > 1 {
		return nil, fmt.Errorf("a %s record's value is one %s, and %q is %d words", recordType, fields[0], value, len(parts))
	}
	data := RData{}
	for i, field := range fields {
		// the last field takes what is left, so a CAA's value may hold spaces
		data[field] = parts[i]
		if i == len(fields)-1 {
			data[field] = strings.Join(parts[i:], " ")
		}
	}

	return data, nil
}

// UpdateSOA sets what a zone's SOA record says: the primary it names, whose
// mailbox it gives, and its times. current is the record as it stands, whose
// TTL and comment are kept; the serial is the server's own to count, and is
// sent as it is.
func (c *Client) UpdateSOA(ctx context.Context, zone string, current *Record, soa SOA) (*Record, error) {
	if zone == "" || current == nil || current.Type != "SOA" {
		return nil, errors.New("zones/records/update: which SOA: it needs its zone and the record as it stands")
	}
	// every field is sent: what an update leaves out is reset
	params := url.Values{"zone": {zone}, "domain": {current.Name}, "type": {"SOA"}, "primaryNameServer": {soa.Primary}, "responsiblePerson": {soa.Responsible}, "serial": {strconv.FormatUint(uint64(current.SOA().Serial), 10)}, "refresh": {strconv.Itoa(soa.Refresh)}, "retry": {strconv.Itoa(soa.Retry)}, "expire": {strconv.Itoa(soa.Expire)}, "minimum": {strconv.Itoa(soa.Minimum)}, "ttl": {strconv.Itoa(current.TTL)}, "comments": {current.Comments}, "disable": {strconv.FormatBool(current.Disabled)}, "expiryTtl": {strconv.Itoa(current.ExpiryTTL)}, "useSerialDateScheme": {strconv.FormatBool(soa.SerialByDate)}}

	var out struct {
		UpdatedRecord Record `json:"updatedRecord"`
	}
	if err := c.write(ctx, "zones/records/update", params, &out); err != nil {
		return nil, err
	}

	return &out.UpdatedRecord, nil
}
