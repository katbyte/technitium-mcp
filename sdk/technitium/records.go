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
}

// RData is a record's data as the API gives it, by field name.
type RData map[string]any

// field is one field of the data as text, "" when it is not there.
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
	default:
		return ""
	}
}

// valueFields are the fields that make up a record's value, by type, in the
// order a zone file writes them. A type not here is written field by field
// (see Value).
var valueFields = map[string][]string{
	"A":     {"ipAddress"},
	"AAAA":  {"ipAddress"},
	"NS":    {"nameServer"},
	"CNAME": {"cname"},
	"PTR":   {"ptrName"},
	"MX":    {"preference", "exchange"},
	"TXT":   {"text"},
	"SRV":   {"priority", "weight", "port", "target"},
	"SOA":   {"primaryNameServer", "responsiblePerson", "serial", "refresh", "retry", "expire", "minimum"},
	"DNAME": {"dname"},
	"ANAME": {"aname"},
	"CAA":   {"flags", "tag", "value"},
	"FWD":   {"protocol", "forwarder"},
	"APP":   {"appName", "classPath"},
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
// 10.0.0.4 for an A, "10 mail.example.com" for an MX. A type this client has
// no layout for is written as its fields by name, so nothing is left out.
func (r *Record) Value() string {
	if fields, ok := valueFields[r.Type]; ok {
		parts := make([]string, 0, len(fields))
		for _, f := range fields {
			parts = append(parts, r.Data.field(f))
		}

		return strings.Join(parts, " ")
	}

	names := make([]string, 0, len(r.Data))
	for name := range r.Data {
		names = append(names, name)
	}
	slices.Sort(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, fmt.Sprintf("%s=%v", name, r.Data[name]))
	}

	return strings.Join(parts, " ")
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

	return SOA{Primary: r.Data.field("primaryNameServer"), Responsible: r.Data.field("responsiblePerson"), Serial: uint32(number("serial")), Refresh: number("refresh"), Retry: number("retry"), Expire: number("expire"), Minimum: number("minimum")} //nolint:gosec // G115: a serial is 32 bits wide by definition
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
	// refuses
	PTR bool
}

// AddRecord adds a record to a zone and returns it as the server now holds
// it.
func (c *Client) AddRecord(ctx context.Context, rec NewRecord) (*Record, error) {
	if rec.Name == "" || rec.Type == "" {
		return nil, errors.New("zones/records/add: a record needs a name and a type")
	}
	params, err := dataParams("zones/records/add", rec.Type, rec.Data, addFields)
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
	if rec.Overwrite {
		params.Set("overwrite", yes)
	}
	if rec.ExpiryTTL > 0 {
		params.Set("expiryTtl", strconv.Itoa(rec.ExpiryTTL))
	}
	if rec.PTR {
		params.Set("ptr", yes)
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
	if rec.Name == "" || rec.Type == "" {
		return errors.New("zones/records/delete: which record: it needs a name and a type")
	}
	params, err := dataParams("zones/records/delete", rec.Type, rec.Data, deleteFields)
	if err != nil {
		return err
	}
	params.Set("domain", rec.Name)
	params.Set("type", rec.Type)
	if zone != "" {
		params.Set("zone", zone)
	}

	return c.write(ctx, "zones/records/delete", params, nil)
}

// addFields are the parameters that carry a record's data when it is added,
// by type; each is spelled as the data's own field is. A type not here is
// one this client cannot write yet.
var addFields = map[string][]string{
	"A":     {"ipAddress"},
	"AAAA":  {"ipAddress"},
	"NS":    {"nameServer"},
	"CNAME": {"cname"},
	"PTR":   {"ptrName"},
	"MX":    {"preference", "exchange"},
	"TXT":   {"text"},
	"SRV":   {"priority", "weight", "port", "target"},
	"DNAME": {"dname"},
	"ANAME": {"aname"},
	"CAA":   {"flags", "tag", "value"},
}

// deleteFields are the parameters that say which record to delete. A name
// holds one CNAME or DNAME at most, so those are deleted by name and type
// alone and the API takes no value for them.
var deleteFields = map[string][]string{
	"A":     {"ipAddress"},
	"AAAA":  {"ipAddress"},
	"NS":    {"nameServer"},
	"CNAME": {},
	"PTR":   {"ptrName"},
	"MX":    {"preference", "exchange"},
	"TXT":   {"text"},
	"SRV":   {"priority", "weight", "port", "target"},
	"DNAME": {},
	"ANAME": {"aname"},
	"CAA":   {"flags", "tag", "value"},
}

// dataParams is a record's data as the parameters a call takes it in. Every
// field the type needs must be there: sent without one, the server would
// answer with an error about a parameter rather than about the record.
func dataParams(path, recordType string, data RData, fields map[string][]string) (url.Values, error) {
	names, ok := fields[recordType]
	if !ok {
		known := make([]string, 0, len(fields))
		for t := range fields {
			known = append(known, t)
		}
		slices.Sort(known)

		return nil, fmt.Errorf("%s: this client cannot write record type %s yet (it writes %s)", path, recordType, strings.Join(known, ", "))
	}

	params := url.Values{}
	for _, name := range names {
		value := data.field(name)
		if value == "" {
			return nil, fmt.Errorf("%s: record type %s needs %s, and %s is not given", path, recordType, strings.Join(names, ", "), name)
		}
		params.Set(name, value)
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
	// Data is the record's data by field, as a Record carries it
	Data RData
}

// UpdateOf is a record as it is, to change and hand to UpdateRecord.
func UpdateOf(rec *Record) RecordUpdate {
	return RecordUpdate{Name: rec.Name, TTL: rec.TTL, Disabled: rec.Disabled, Comments: rec.Comments, ExpiryTTL: rec.ExpiryTTL, Data: maps.Clone(rec.Data)}
}

// newFields are the parameters an update takes a record's new data in, by
// the field each replaces. A CNAME and a DNAME are the one record at their
// name, so the update takes their new target under the field's own name and
// no old one.
var newFields = map[string]string{
	"ipAddress":  "newIpAddress",
	"nameServer": "newNameServer",
	"ptrName":    "newPtrName",
	"preference": "newPreference",
	"exchange":   "newExchange",
	"text":       "newText",
	"priority":   "newPriority",
	"weight":     "newWeight",
	"port":       "newPort",
	"target":     "newTarget",
	"aname":      "newAName",
	"flags":      "newFlags",
	"tag":        "newTag",
	"value":      "newValue",
	"cname":      "cname",
	"dname":      "dname",
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
	params, err := dataParams("zones/records/update", current.Type, current.Data, deleteFields)
	if err != nil {
		return nil, err
	}
	fresh, err := dataParams("zones/records/update", current.Type, want.Data, addFields)
	if err != nil {
		return nil, err
	}
	for field, values := range fresh {
		params.Set(newFields[field], values[0])
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

// WritableTypes are the record types this client can add, change and delete.
func WritableTypes() []string {
	types := make([]string, 0, len(addFields))
	for t := range addFields {
		types = append(types, t)
	}
	slices.Sort(types)

	return types
}

// ParseValue reads a record's data from its value on one line, as Value
// writes one: an address for an A, "10 mail.example.com" for an MX. A TXT
// record's value is its whole text, spaces and all.
func ParseValue(recordType, value string) (RData, error) {
	fields, ok := addFields[recordType]
	if !ok {
		return nil, fmt.Errorf("this client cannot write record type %s yet (it writes %s)", recordType, strings.Join(WritableTypes(), ", "))
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("a %s record's value is %s, and none was given", recordType, strings.Join(fields, " "))
	}
	if recordType == "TXT" {
		return RData{"text": value}, nil
	}

	// the last field takes what is left, so a CAA's value may hold spaces
	parts := strings.Fields(value)
	if len(parts) < len(fields) {
		return nil, fmt.Errorf("a %s record's value is %s, and %q is %d of those", recordType, strings.Join(fields, " "), value, len(parts))
	}
	if len(fields) == 1 && len(parts) > 1 {
		return nil, fmt.Errorf("a %s record's value is one %s, and %q is %d words", recordType, fields[0], value, len(parts))
	}
	data := RData{}
	for i, field := range fields {
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
	params := url.Values{"zone": {zone}, "domain": {current.Name}, "type": {"SOA"}, "primaryNameServer": {soa.Primary}, "responsiblePerson": {soa.Responsible}, "serial": {strconv.FormatUint(uint64(current.SOA().Serial), 10)}, "refresh": {strconv.Itoa(soa.Refresh)}, "retry": {strconv.Itoa(soa.Retry)}, "expire": {strconv.Itoa(soa.Expire)}, "minimum": {strconv.Itoa(soa.Minimum)}, "ttl": {strconv.Itoa(current.TTL)}, "comments": {current.Comments}, "disable": {strconv.FormatBool(current.Disabled)}, "expiryTtl": {strconv.Itoa(current.ExpiryTTL)}}

	var out struct {
		UpdatedRecord Record `json:"updatedRecord"`
	}
	if err := c.write(ctx, "zones/records/update", params, &out); err != nil {
		return nil, err
	}

	return &out.UpdatedRecord, nil
}
