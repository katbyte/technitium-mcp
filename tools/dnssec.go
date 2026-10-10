package tools

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/katbyte/technitium-mcp/lib/servers"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// signingKey is one of a signed zone's keys as a tool gives it.
type signingKey struct {
	KeyTag       int    `json:"key_tag"                 jsonschema:"the key's tag, which the key tools name it by"`
	Type         string `json:"type"                    jsonschema:"KeySigningKey, which signs the zone's keys and is the one the parent zone vouches for, or ZoneSigningKey, which signs the records"`
	Algorithm    string `json:"algorithm"`
	State        string `json:"state"                   jsonschema:"how far the key has come: Generated (made, not in the zone), Published (in the zone, not yet used), Ready (a key signing key waiting for its DS record at the parent), Active (in use), Retired or Revoked (on its way out)"`
	ChangedOn    string `json:"changed_on,omitempty"    jsonschema:"when the state last changed, UTC"`
	ReadyBy      string `json:"ready_by,omitempty"      jsonschema:"when a key on its way will be ready, UTC"`
	Retiring     bool   `json:"retiring,omitempty"      jsonschema:"the key is being replaced and goes once its successor is in use"`
	RolloverDays int    `json:"rollover_days,omitempty" jsonschema:"how often the server replaces the key by itself; absent for never"`
}

// dsRecord is what a signed zone's parent is to hold for a key signing key.
type dsRecord struct {
	KeyTag    int      `json:"key_tag"`
	KeyState  string   `json:"key_state"`
	ReadyBy   string   `json:"ready_by,omitempty"`
	Algorithm string   `json:"algorithm"`
	PublicKey string   `json:"public_key"`
	Digests   []string `json:"digests"            jsonschema:"each digest as its type and its hex: what a registrar is given"`
}

// zoneSigning is how one server has a zone signed.
type zoneSigning struct {
	Server    string       `json:"server"`
	Type      string       `json:"type,omitempty"       jsonschema:"what the zone is on this server: only a primary holds keys, and a copy holds the signatures it was sent"`
	Status    string       `json:"status,omitempty"     jsonschema:"Unsigned, SignedWithNSEC or SignedWithNSEC3"`
	DNSKeyTTL int          `json:"dnskey_ttl,omitempty"`
	Keys      []signingKey `json:"keys,omitempty"`
	DS        []dsRecord   `json:"ds,omitempty"         jsonschema:"what the zone's parent is to hold: the zone is trusted by nobody until it does"`
	Error     string       `json:"error,omitempty"`
}

// signingOf reads how a server has a zone signed; nil for a server that does
// not hold the zone.
func signingOf(ctx context.Context, srv *servers.Server, zone string) (*zoneSigning, error) {
	zones, err := srv.Client.Zones(ctx, technitium.ZoneFilter{})
	if err != nil {
		return nil, err
	}
	i := slices.IndexFunc(zones, func(z technitium.Zone) bool { return sameName(z.Name, zone) })
	if i < 0 {
		return nil, nil //nolint:nilnil // a server that does not hold the zone is no error: it is said beside the ones that do
	}

	return signingOfHeld(ctx, srv, &zones[i])
}

// signingOfHeld reads how a server has signed a zone it is known to hold.
func signingOfHeld(ctx context.Context, srv *servers.Server, held *technitium.Zone) (*zoneSigning, error) {
	out := &zoneSigning{Server: srv.Name, Type: held.Type, Status: held.DNSSECStatus}
	// only a primary has keys to read; a copy is signed by what it was sent
	if held.Type != technitium.ZonePrimary {
		return out, nil
	}

	how, err := srv.Client.DNSSEC(ctx, held.Name)
	if err != nil {
		return nil, err
	}
	out.Status, out.DNSKeyTTL = how.DNSSECStatus, how.DNSKeyTTL
	for _, k := range how.Keys {
		out.Keys = append(out.Keys, signingKey{KeyTag: k.KeyTag, Type: k.KeyType, Algorithm: k.Algorithm, State: k.State, ChangedOn: utc(k.StateChangedOn), ReadyBy: utc(k.StateReadyBy), Retiring: k.IsRetiring, RolloverDays: k.RolloverDays})
	}
	if !held.Signed() {
		return out, nil
	}
	ds, err := srv.Client.DSInfo(ctx, held.Name)
	if err != nil {
		return nil, err
	}
	for _, record := range ds.DSRecords {
		row := dsRecord{KeyTag: record.KeyTag, KeyState: record.DNSKeyState, ReadyBy: utc(record.DNSKeyStateReadyBy), Algorithm: record.Algorithm, PublicKey: record.PublicKey, Digests: []string{}}
		for _, digest := range record.Digests {
			row.Digests = append(row.Digests, digest.DigestType+" "+digest.Digest)
		}
		out.DS = append(out.DS, row)
	}

	return out, nil
}

// signedPrimary is a zone on the one server a change to its signing is made
// on, which must hold it as a primary.
func (r *registry) signedPrimary(ctx context.Context, server, zoneArg string) (*servers.Server, *technitium.Zone, error) {
	zone := cleanName(zoneArg)
	if zone == "" {
		return nil, nil, errors.New("which zone: give its name, as zone_list gives it")
	}
	srv, held, err := r.zoneOn(ctx, server, zone)
	if err != nil {
		return nil, nil, err
	}
	if held.Type != technitium.ZonePrimary {
		return nil, nil, fmt.Errorf("%s holds %s as a %s zone: a zone is signed, and its keys kept, where it is a primary, which zone_list names", srv.Name, held.Name, held.Type)
	}

	return srv, held, nil
}

// keyOptionsOf reads how a key is to be made from a tool's arguments.
func keyOptionsOf(algorithm, hash, curve string) (technitium.KeyOptions, error) {
	algorithm = strings.ToUpper(strings.TrimSpace(algorithm))
	if algorithm == "" {
		algorithm = technitium.AlgorithmECDSA
	}
	options := technitium.KeyOptions{Algorithm: algorithm, HashAlgorithm: strings.ToUpper(strings.TrimSpace(hash)), Curve: strings.ToUpper(strings.TrimSpace(curve))}
	switch algorithm {
	case technitium.AlgorithmRSA:
		if options.HashAlgorithm == "" {
			options.HashAlgorithm = "SHA256"
		}
		options.Curve = ""
	case technitium.AlgorithmECDSA:
		if options.Curve == "" {
			options.Curve = "P256"
		}
		options.HashAlgorithm = ""
	case technitium.AlgorithmEDDSA:
		if options.Curve == "" {
			options.Curve = "ED25519"
		}
		options.HashAlgorithm = ""
	default:
		return options, fmt.Errorf("algorithm %q: a zone is signed with ECDSA (the default), EDDSA or RSA", algorithm)
	}

	return options, nil
}

// signingChangeOut is what the tools that change a zone's signing answer
// with.
type signingChangeOut struct {
	Server  string       `json:"server"`
	Zone    string       `json:"zone"`
	Changed bool         `json:"changed"         jsonschema:"something was changed; with a dry run, something would be"`
	Changes []string     `json:"changes"         jsonschema:"each change made; with a dry run, each that would be"`
	After   *zoneSigning `json:"after,omitempty" jsonschema:"the zone's signing as the server has it now, read back; absent from a dry run"`
	Note    string       `json:"note,omitempty"`
}

func registerDNSSECTools(r *registry) {
	type dnssecGetIn struct {
		serverArg

		Zone string `json:"zone" jsonschema:"the zone's name, as zone_list gives it"`
	}
	type dnssecGetOut struct {
		Zone      string        `json:"zone"`
		Servers   []zoneSigning `json:"servers"              jsonschema:"each server holding the zone, with how it is signed there"`
		MissingOn []string      `json:"missing_on,omitempty" jsonschema:"the servers asked that do not hold the zone"`
	}
	add(r, readTool, &mcp.Tool{
		Name:        "dnssec_get",
		Description: "How a zone is signed with DNSSEC on each server holding it: whether it is, how it proves a name is not there, every key with its state and when the server next replaces it, and the DS records the parent zone must hold - the thing to give a registrar. A zone is signed on its primary, which is the only server with keys; a copy says what it was sent. A zone that is not signed answers Unsigned.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in dnssecGetIn) (*mcp.CallToolResult, dnssecGetOut, error) {
		zone := cleanName(in.Zone)
		if zone == "" {
			return nil, dnssecGetOut{}, errors.New("which zone: give its name, as zone_list gives it")
		}
		picked, err := r.servers.Pick(in.Server)
		if err != nil {
			return nil, dnssecGetOut{}, err
		}
		answers := ask(ctx, picked, func(ctx context.Context, srv *servers.Server) (*zoneSigning, error) {
			return signingOf(ctx, srv, zone)
		})
		if _, err := failures(answers); err != nil {
			return nil, dnssecGetOut{}, err
		}

		out := dnssecGetOut{Zone: zone, Servers: []zoneSigning{}}
		for _, a := range answers {
			switch {
			case a.Err != nil:
				out.Servers = append(out.Servers, zoneSigning{Server: a.Server.Name, Error: a.Err.Error()})
			case a.Value == nil:
				out.MissingOn = append(out.MissingOn, a.Server.Name)
			default:
				out.Servers = append(out.Servers, *a.Value)
			}
		}
		if len(out.MissingOn) == len(answers) {
			return nil, dnssecGetOut{}, fmt.Errorf("no server asked holds a zone named %s: zone_list names the zones each holds", zone)
		}

		return nil, out, nil
	})

	type dnssecSignIn struct {
		writeServerArg

		Zone            string `json:"zone"                        jsonschema:"the zone's name, as zone_list gives it: a primary"`
		Algorithm       string `json:"algorithm,omitempty"         jsonschema:"ECDSA (the default), EDDSA or RSA"`
		Curve           string `json:"curve,omitempty"             jsonschema:"for ECDSA, P256 (the default) or P384; for EDDSA, ED25519 (the default) or ED448"`
		HashAlgorithm   string `json:"hash_algorithm,omitempty"    jsonschema:"for RSA: SHA256 (the default) or SHA512"`
		KSKKeySize      int    `json:"ksk_key_size,omitempty"      jsonschema:"for RSA: the key signing key's size in bits, 2048 by default"`
		ZSKKeySize      int    `json:"zsk_key_size,omitempty"      jsonschema:"for RSA: the zone signing key's size in bits, 1280 by default"`
		NXProof         string `json:"nx_proof,omitempty"          jsonschema:"how the zone proves a name is not in it: NSEC (the default), which lets anyone list the zone's names, or NSEC3, which hides them"`
		Iterations      int    `json:"iterations,omitempty"        jsonschema:"for NSEC3: how many more times a name is hashed, 0 by default as is advised"`
		SaltLength      int    `json:"salt_length,omitempty"       jsonschema:"for NSEC3: the salt's length in bytes, 0 by default as is advised"`
		DNSKeyTTL       int    `json:"dnskey_ttl,omitempty"        jsonschema:"the TTL of the zone's DNSKEY records in seconds, the server's own day by default"`
		ZSKRolloverDays *int   `json:"zsk_rollover_days,omitempty" jsonschema:"how often the server replaces the zone signing key by itself, 0 to 365 where 0 is never; the server's own 30 by default"`
		DryRun          bool   `json:"dry_run,omitempty"           jsonschema:"sign nothing, and answer with what would be"`
	}
	add(r, writeTool, &mcp.Tool{
		Name:        "dnssec_sign",
		Description: "Sign a primary zone with DNSSEC. The server makes a key signing key and a zone signing key, signs every record, and keeps the signatures fresh from then on. The zone is not trusted by anyone until its DS record is at its parent zone: the answer has it under after.ds, to be given to the registrar or put in the parent zone, once the key signing key's state is Ready. Until then the zone resolves as an unsigned one does. A zone that is signed already is refused: dnssec_edit and the key tools change one.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in dnssecSignIn) (*mcp.CallToolResult, signingChangeOut, error) {
		srv, held, err := r.signedPrimary(ctx, in.Server, in.Zone)
		if err != nil {
			return nil, signingChangeOut{}, err
		}
		if held.Signed() {
			return nil, signingChangeOut{}, fmt.Errorf("%s is signed already on %s (%s): dnssec_get shows its keys, and dnssec_edit and the key tools change them", held.Name, srv.Name, held.DNSSECStatus)
		}
		options, err := keyOptionsOf(in.Algorithm, in.HashAlgorithm, in.Curve)
		if err != nil {
			return nil, signingChangeOut{}, err
		}
		proof := strings.ToUpper(strings.TrimSpace(in.NXProof))
		if proof != "" && proof != technitium.ProofNSEC && proof != technitium.ProofNSEC3 {
			return nil, signingChangeOut{}, fmt.Errorf("nx_proof %q: it is NSEC or NSEC3", in.NXProof)
		}
		if in.ZSKRolloverDays != nil && (*in.ZSKRolloverDays < 0 || *in.ZSKRolloverDays > 365) {
			return nil, signingChangeOut{}, errors.New("zsk_rollover_days is 0 to 365, where 0 is never")
		}
		how := technitium.Signing{KeyOptions: options, NXProof: proof, Iterations: in.Iterations, SaltLength: in.SaltLength, DNSKeyTTL: in.DNSKeyTTL, ZSKRolloverDays: in.ZSKRolloverDays}
		with := options.Algorithm + " " + options.Curve
		if options.Algorithm == technitium.AlgorithmRSA {
			how.KSKKeySize, how.ZSKKeySize = in.KSKKeySize, in.ZSKKeySize
			if how.KSKKeySize == 0 {
				how.KSKKeySize = 2048
			}
			if how.ZSKKeySize == 0 {
				how.ZSKKeySize = 1280
			}
			with = fmt.Sprintf("RSA %s with keys of %d and %d bits", options.HashAlgorithm, how.KSKKeySize, how.ZSKKeySize)
		}
		if proof == "" {
			proof = technitium.ProofNSEC
		}

		out := signingChangeOut{Server: srv.Name, Zone: held.Name, Changed: true, Note: "the zone is trusted by nobody until its parent holds the DS record under after.ds, which is given to it once the key signing key is Ready; dnssec_get shows the key's state"}
		done := &changes{dry: in.DryRun}
		if done.did("signed %s on %s with %s, proving what is not there with %s", held.Name, srv.Name, strings.TrimSpace(with), proof) {
			if err := srv.Client.SignZone(ctx, held.Name, how); err != nil {
				return nil, signingChangeOut{}, fmt.Errorf("signing %s: %w", held.Name, err)
			}
			if out.After, err = signingOf(ctx, srv, held.Name); err != nil {
				return nil, signingChangeOut{}, fmt.Errorf("the zone was signed and could not be read back: %w", err)
			}
		}
		out.Changes = done.said

		return nil, out, nil
	})

	type dnssecUnsignIn struct {
		writeServerArg

		Zone   string `json:"zone"              jsonschema:"the zone's name, as zone_list gives it"`
		DryRun bool   `json:"dry_run,omitempty" jsonschema:"change nothing, and answer with what would be"`
	}
	add(r, deleteTool, &mcp.Tool{
		Name:        "dnssec_unsign",
		Description: "Take DNSSEC off a primary zone: its keys are deleted for good and its signatures removed. Take the zone's DS record out of its parent zone first and wait for it to expire there: a zone whose parent still vouches for a key it no longer has stops resolving for everyone who validates, which is most of the internet. With dry_run it changes nothing and lists the keys that would go.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in dnssecUnsignIn) (*mcp.CallToolResult, signingChangeOut, error) {
		srv, held, err := r.signedPrimary(ctx, in.Server, in.Zone)
		if err != nil {
			return nil, signingChangeOut{}, err
		}
		out := signingChangeOut{Server: srv.Name, Zone: held.Name, Changes: []string{}}
		if !held.Signed() {
			out.Note = "the zone is not signed: there is nothing to take off"

			return nil, out, nil
		}
		before, err := signingOf(ctx, srv, held.Name)
		if err != nil {
			return nil, signingChangeOut{}, err
		}

		out.Changed, out.Note = true, "if the zone's parent still holds its DS record, the zone no longer resolves for anyone who validates until that record is gone"
		done := &changes{dry: in.DryRun}
		if done.did("removed DNSSEC from %s on %s, deleting its %d keys", held.Name, srv.Name, len(before.Keys)) {
			if err := srv.Client.UnsignZone(ctx, held.Name); err != nil {
				return nil, signingChangeOut{}, fmt.Errorf("unsigning %s: %w", held.Name, err)
			}
			if out.After, err = signingOf(ctx, srv, held.Name); err != nil {
				return nil, signingChangeOut{}, fmt.Errorf("DNSSEC was taken off and the zone could not be read back: %w", err)
			}
		}
		out.Changes = done.said

		return nil, out, nil
	})

	type dnssecEditIn struct {
		writeServerArg

		Zone       string `json:"zone"                  jsonschema:"the zone's name, as zone_list gives it: a signed primary"`
		NXProof    string `json:"nx_proof,omitempty"    jsonschema:"change how the zone proves a name is not in it: NSEC or NSEC3"`
		Iterations *int   `json:"iterations,omitempty"  jsonschema:"for a zone on NSEC3, or being put on it: how many more times a name is hashed"`
		SaltLength *int   `json:"salt_length,omitempty" jsonschema:"for a zone on NSEC3, or being put on it: the salt's length in bytes"`
		DNSKeyTTL  int    `json:"dnskey_ttl,omitempty"  jsonschema:"the TTL of the zone's DNSKEY records in seconds. The server changes it only while every key is Ready or Active, and refuses otherwise"`
		DryRun     bool   `json:"dry_run,omitempty"     jsonschema:"change nothing, and answer with what would be"`
	}
	add(r, writeTool, &mcp.Tool{
		Name:        "dnssec_edit",
		Description: "Change how a signed zone is signed, leaving its keys as they are: how it proves a name is not there (NSEC, or NSEC3 with its iterations and salt), and the TTL of its DNSKEY records. Only what is given is changed. The keys themselves are the key tools' (dnssec_key_add, dnssec_key_edit, dnssec_key_delete).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in dnssecEditIn) (*mcp.CallToolResult, signingChangeOut, error) {
		srv, held, err := r.signedPrimary(ctx, in.Server, in.Zone)
		if err != nil {
			return nil, signingChangeOut{}, err
		}
		if !held.Signed() {
			return nil, signingChangeOut{}, fmt.Errorf("%s is not signed on %s: dnssec_sign signs it", held.Name, srv.Name)
		}
		proof := strings.ToUpper(strings.TrimSpace(in.NXProof))
		if proof != "" && proof != technitium.ProofNSEC && proof != technitium.ProofNSEC3 {
			return nil, signingChangeOut{}, fmt.Errorf("nx_proof %q: it is NSEC or NSEC3", in.NXProof)
		}
		if proof == "" && in.Iterations == nil && in.SaltLength == nil && in.DNSKeyTTL == 0 {
			return nil, signingChangeOut{}, errors.New("nothing was given to change: nx_proof, iterations, salt_length or dnskey_ttl")
		}
		onNSEC3 := held.DNSSECStatus == "SignedWithNSEC3"
		toNSEC3 := proof == technitium.ProofNSEC3 || (proof == "" && onNSEC3)
		if (in.Iterations != nil || in.SaltLength != nil) && !toNSEC3 {
			return nil, signingChangeOut{}, errors.New("iterations and salt_length are NSEC3's, and the zone is on NSEC: give nx_proof NSEC3 with them to change it over")
		}

		out := signingChangeOut{Server: srv.Name, Zone: held.Name}
		done := &changes{dry: in.DryRun}
		switch {
		case proof == technitium.ProofNSEC3 && !onNSEC3:
			if done.did("changed %s on %s from NSEC to NSEC3", held.Name, srv.Name) {
				if err := srv.Client.ConvertToNSEC3(ctx, held.Name); err != nil {
					return nil, signingChangeOut{}, fmt.Errorf("converting %s to NSEC3: %w", held.Name, err)
				}
			}
		case proof == technitium.ProofNSEC && onNSEC3:
			if done.did("changed %s on %s from NSEC3 to NSEC", held.Name, srv.Name) {
				if err := srv.Client.ConvertToNSEC(ctx, held.Name); err != nil {
					return nil, signingChangeOut{}, fmt.Errorf("converting %s to NSEC: %w", held.Name, err)
				}
			}
		default:
		}
		if in.Iterations != nil || in.SaltLength != nil {
			iterations, salt := 0, 0
			if in.Iterations != nil {
				iterations = *in.Iterations
			}
			if in.SaltLength != nil {
				salt = *in.SaltLength
			}
			if done.did("set the NSEC3 of %s on %s to %d iterations and a salt of %d bytes", held.Name, srv.Name, iterations, salt) {
				if err := srv.Client.UpdateNSEC3Params(ctx, held.Name, iterations, salt); err != nil {
					return nil, signingChangeOut{}, fmt.Errorf("setting the NSEC3 of %s: %w", held.Name, err)
				}
			}
		}
		if in.DNSKeyTTL != 0 {
			if done.did("set the TTL of the DNSKEY records of %s on %s to %d seconds", held.Name, srv.Name, in.DNSKeyTTL) {
				if err := srv.Client.UpdateDNSKeyTTL(ctx, held.Name, in.DNSKeyTTL); err != nil {
					return nil, signingChangeOut{}, fmt.Errorf("setting the DNSKEY TTL of %s: %w", held.Name, err)
				}
			}
		}
		out.Changes, out.Changed = done.said, len(done.said) > 0
		if out.Changes == nil {
			out.Changes = []string{}
		}
		if !in.DryRun {
			if out.After, err = signingOf(ctx, srv, held.Name); err != nil {
				return nil, signingChangeOut{}, fmt.Errorf("the zone could not be read back: %w", err)
			}
		}

		return nil, out, nil
	})

	type dnssecKeyAddIn struct {
		writeServerArg

		Zone          string `json:"zone"                     jsonschema:"the zone's name, as zone_list gives it: a signed primary"`
		KeyType       string `json:"key_type"                 jsonschema:"KeySigningKey or ZoneSigningKey"`
		Algorithm     string `json:"algorithm,omitempty"      jsonschema:"ECDSA (the default), EDDSA or RSA"`
		Curve         string `json:"curve,omitempty"          jsonschema:"for ECDSA, P256 (the default) or P384; for EDDSA, ED25519 (the default) or ED448"`
		HashAlgorithm string `json:"hash_algorithm,omitempty" jsonschema:"for RSA: SHA256 (the default) or SHA512"`
		KeySize       int    `json:"key_size,omitempty"       jsonschema:"for RSA: the key's size in bits, 2048 for a key signing key and 1280 for a zone signing key by default"`
		RolloverDays  *int   `json:"rollover_days,omitempty"  jsonschema:"how often the server replaces the key by itself, 0 to 365 where 0 is never"`
		Publish       bool   `json:"publish,omitempty"        jsonschema:"put the key in the zone at once. Without it the key is only generated, and dnssec_key_edit publishes it later"`
		DryRun        bool   `json:"dry_run,omitempty"        jsonschema:"change nothing, and answer with what would be"`
	}
	add(r, writeTool, &mcp.Tool{
		Name:        "dnssec_key_add",
		Description: "Add a key to a signed zone: a new key signing key or zone signing key the server makes. It is only generated until it is published, which puts it in the zone as a DNSKEY record; from there the server brings it into use by itself. A new key signing key waits at Ready for its DS record (dnssec_get gives it) to be at the parent zone. To replace a key in one step use dnssec_key_edit with action rollover.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in dnssecKeyAddIn) (*mcp.CallToolResult, signingChangeOut, error) {
		srv, held, err := r.signedPrimary(ctx, in.Server, in.Zone)
		if err != nil {
			return nil, signingChangeOut{}, err
		}
		if !held.Signed() {
			return nil, signingChangeOut{}, fmt.Errorf("%s is not signed on %s: dnssec_sign signs it, and makes its first keys", held.Name, srv.Name)
		}
		var keyType string
		switch strings.ToLower(strings.TrimSpace(in.KeyType)) {
		case "keysigningkey", "ksk":
			keyType = technitium.KeySigningKey
		case "zonesigningkey", "zsk":
			keyType = technitium.ZoneSigningKey
		default:
			return nil, signingChangeOut{}, fmt.Errorf("key_type %q: it is KeySigningKey or ZoneSigningKey", in.KeyType)
		}
		options, err := keyOptionsOf(in.Algorithm, in.HashAlgorithm, in.Curve)
		if err != nil {
			return nil, signingChangeOut{}, err
		}
		if in.RolloverDays != nil && (*in.RolloverDays < 0 || *in.RolloverDays > 365) {
			return nil, signingChangeOut{}, errors.New("rollover_days is 0 to 365, where 0 is never")
		}
		key := technitium.NewSigningKey{KeyOptions: options, KeyType: keyType, RolloverDays: in.RolloverDays}
		if options.Algorithm == technitium.AlgorithmRSA {
			if key.KeySize = in.KeySize; key.KeySize == 0 {
				key.KeySize = 1280
				if keyType == technitium.KeySigningKey {
					key.KeySize = 2048
				}
			}
		}

		out := signingChangeOut{Server: srv.Name, Zone: held.Name, Changed: true}
		done := &changes{dry: in.DryRun}
		if done.did("added a %s %s to %s on %s", options.Algorithm, keyType, held.Name, srv.Name) {
			if err := srv.Client.AddSigningKey(ctx, held.Name, key); err != nil {
				return nil, signingChangeOut{}, fmt.Errorf("adding a key to %s: %w", held.Name, err)
			}
		}
		if in.Publish && done.did("published the keys of %s that were only generated", held.Name) {
			if err := srv.Client.PublishSigningKeys(ctx, held.Name); err != nil {
				return nil, signingChangeOut{}, fmt.Errorf("the key was added, and publishing it failed: %w", err)
			}
		}
		out.Changes = done.said
		if !in.DryRun {
			if out.After, err = signingOf(ctx, srv, held.Name); err != nil {
				return nil, signingChangeOut{}, fmt.Errorf("the key was added and the zone could not be read back: %w", err)
			}
		}

		return nil, out, nil
	})

	type dnssecKeyEditIn struct {
		writeServerArg

		Zone         string `json:"zone"                    jsonschema:"the zone's name, as zone_list gives it: a signed primary"`
		Action       string `json:"action,omitempty"        jsonschema:"publish: put every key that is only generated into the zone; rollover: replace the key named with a new one, which the server brings in before it takes the old one out; retire: take the key named out once another of its kind is in use. Leave it out to only set rollover_days"`
		KeyTag       int    `json:"key_tag,omitempty"       jsonschema:"the key, by the tag dnssec_get gives it: needed for everything but publish"`
		RolloverDays *int   `json:"rollover_days,omitempty" jsonschema:"how often the server replaces the key named by itself, 0 to 365 where 0 is never"`
		DryRun       bool   `json:"dry_run,omitempty"       jsonschema:"change nothing, and answer with what would be"`
	}
	add(r, writeTool, &mcp.Tool{
		Name:        "dnssec_key_edit",
		Description: "Move a signed zone's keys along: publish the keys that were only generated, roll a key over to a new one, retire a key, or set how often the server replaces a key by itself. The server refuses what is not safe yet - a key is retired only once another of its kind is Active - and says why. After a key signing key is rolled over the parent zone needs the new key's DS record (dnssec_get gives it) before the old one goes.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in dnssecKeyEditIn) (*mcp.CallToolResult, signingChangeOut, error) {
		srv, held, err := r.signedPrimary(ctx, in.Server, in.Zone)
		if err != nil {
			return nil, signingChangeOut{}, err
		}
		if !held.Signed() {
			return nil, signingChangeOut{}, fmt.Errorf("%s is not signed on %s: it has no keys", held.Name, srv.Name)
		}
		action := strings.ToLower(strings.TrimSpace(in.Action))
		if !slices.Contains([]string{"", "publish", "rollover", "retire"}, action) {
			return nil, signingChangeOut{}, fmt.Errorf("action %q: it is publish, rollover or retire", in.Action)
		}
		if action == "" && in.RolloverDays == nil {
			return nil, signingChangeOut{}, errors.New("nothing was given to do: an action, or rollover_days for a key")
		}
		if in.RolloverDays != nil && (*in.RolloverDays < 0 || *in.RolloverDays > 365) {
			return nil, signingChangeOut{}, errors.New("rollover_days is 0 to 365, where 0 is never")
		}
		before, err := signingOf(ctx, srv, held.Name)
		if err != nil {
			return nil, signingChangeOut{}, err
		}
		named := slices.IndexFunc(before.Keys, func(k signingKey) bool { return k.KeyTag == in.KeyTag })
		if (action == "rollover" || action == "retire" || in.RolloverDays != nil) && named < 0 {
			return nil, signingChangeOut{}, fmt.Errorf("%s has no key with the tag %d: dnssec_get lists its keys", held.Name, in.KeyTag)
		}

		out := signingChangeOut{Server: srv.Name, Zone: held.Name}
		done := &changes{dry: in.DryRun}
		if in.RolloverDays != nil && before.Keys[named].RolloverDays != *in.RolloverDays {
			every := fmt.Sprintf("every %d days", *in.RolloverDays)
			if *in.RolloverDays == 0 {
				every = "never"
			}
			if done.did("set the key %d of %s to be replaced %s", in.KeyTag, held.Name, every) {
				if err := srv.Client.UpdateSigningKey(ctx, held.Name, in.KeyTag, *in.RolloverDays); err != nil {
					return nil, signingChangeOut{}, fmt.Errorf("setting the key's rollover: %w", err)
				}
			}
		}
		switch action {
		case "publish":
			generated := 0
			for _, k := range before.Keys {
				if k.State == "Generated" {
					generated++
				}
			}
			if generated > 0 && done.did("published the %d keys of %s that were only generated", generated, held.Name) {
				if err := srv.Client.PublishSigningKeys(ctx, held.Name); err != nil {
					return nil, signingChangeOut{}, fmt.Errorf("publishing the keys of %s: %w", held.Name, err)
				}
			}
		case "rollover":
			if done.did("rolled the %s %d of %s over to a new key", before.Keys[named].Type, in.KeyTag, held.Name) {
				if err := srv.Client.RolloverDNSKey(ctx, held.Name, in.KeyTag); err != nil {
					return nil, signingChangeOut{}, fmt.Errorf("rolling the key over: %w", err)
				}
			}
		case "retire":
			if done.did("retired the %s %d of %s", before.Keys[named].Type, in.KeyTag, held.Name) {
				if err := srv.Client.RetireDNSKey(ctx, held.Name, in.KeyTag); err != nil {
					return nil, signingChangeOut{}, fmt.Errorf("retiring the key: %w", err)
				}
			}
		default:
		}
		out.Changes, out.Changed = done.said, len(done.said) > 0
		if out.Changes == nil {
			out.Changes = []string{}
		}
		if !in.DryRun {
			if out.After, err = signingOf(ctx, srv, held.Name); err != nil {
				return nil, signingChangeOut{}, fmt.Errorf("the zone could not be read back: %w", err)
			}
		}

		return nil, out, nil
	})

	type dnssecKeyDeleteIn struct {
		writeServerArg

		Zone   string `json:"zone"              jsonschema:"the zone's name, as zone_list gives it: a signed primary"`
		KeyTag int    `json:"key_tag"           jsonschema:"the key, by the tag dnssec_get gives it"`
		DryRun bool   `json:"dry_run,omitempty" jsonschema:"delete nothing, and answer with what would be"`
	}
	add(r, deleteTool, &mcp.Tool{
		Name:        "dnssec_key_delete",
		Description: "Delete one of a signed zone's keys that was only generated and never published: a key added by mistake. A key that has been in the zone cannot be deleted, since resolvers may still hold it: it is retired instead (dnssec_key_edit with action retire), and the server takes it out when that is safe.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in dnssecKeyDeleteIn) (*mcp.CallToolResult, signingChangeOut, error) {
		srv, held, err := r.signedPrimary(ctx, in.Server, in.Zone)
		if err != nil {
			return nil, signingChangeOut{}, err
		}
		before, err := signingOf(ctx, srv, held.Name)
		if err != nil {
			return nil, signingChangeOut{}, err
		}
		named := slices.IndexFunc(before.Keys, func(k signingKey) bool { return k.KeyTag == in.KeyTag })
		if named < 0 {
			return nil, signingChangeOut{}, fmt.Errorf("%s has no key with the tag %d: dnssec_get lists its keys", held.Name, in.KeyTag)
		}
		if state := before.Keys[named].State; state != "Generated" {
			return nil, signingChangeOut{}, fmt.Errorf("the key %d of %s is %s: only a key that was generated and never published is deleted. One that has been in the zone is retired, with dnssec_key_edit", in.KeyTag, held.Name, state)
		}

		out := signingChangeOut{Server: srv.Name, Zone: held.Name, Changed: true}
		done := &changes{dry: in.DryRun}
		if done.did("deleted the %s %d of %s on %s, which was only generated", before.Keys[named].Type, in.KeyTag, held.Name, srv.Name) {
			if err := srv.Client.DeleteSigningKey(ctx, held.Name, in.KeyTag); err != nil {
				return nil, signingChangeOut{}, fmt.Errorf("deleting the key: %w", err)
			}
			if out.After, err = signingOf(ctx, srv, held.Name); err != nil {
				return nil, signingChangeOut{}, fmt.Errorf("the key was deleted and the zone could not be read back: %w", err)
			}
		}
		out.Changes = done.said

		return nil, out, nil
	})
}
