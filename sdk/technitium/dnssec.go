package technitium

import (
	"context"
	"errors"
	"net/url"
	"strconv"
)

// The ways a zone is signed, and the two proofs that a name is not there.
const (
	AlgorithmRSA   = "RSA"
	AlgorithmECDSA = "ECDSA"
	AlgorithmEDDSA = "EDDSA"

	ProofNSEC  = "NSEC"
	ProofNSEC3 = "NSEC3"

	KeySigningKey  = "KeySigningKey"
	ZoneSigningKey = "ZoneSigningKey"
)

// KeyOptions is how a signing key is made. RSA takes a hash and a size, and
// the other two a curve: P256 or P384 for ECDSA, ED25519 or ED448 for EDDSA.
type KeyOptions struct {
	// Algorithm is RSA, ECDSA or EDDSA
	Algorithm string
	// HashAlgorithm is RSA's: MD5, SHA1, SHA256 or SHA512
	HashAlgorithm string
	Curve         string
}

func (k KeyOptions) params(path string, params url.Values) error {
	switch {
	case k.Algorithm == "":
		return errors.New(path + ": which algorithm: RSA, ECDSA or EDDSA")
	case k.Algorithm == AlgorithmRSA && k.HashAlgorithm == "":
		return errors.New(path + ": RSA takes a hash algorithm: SHA256 or SHA512")
	case k.Algorithm != AlgorithmRSA && k.Curve == "":
		return errors.New(path + ": " + k.Algorithm + " takes a curve: P256 or P384 for ECDSA, ED25519 or ED448 for EDDSA")
	default:
	}
	params.Set("algorithm", k.Algorithm)
	set(params, map[string]string{"hashAlgorithm": k.HashAlgorithm, "curve": k.Curve})

	return nil
}

// Signing is how a zone is signed.
type Signing struct {
	KeyOptions

	// KSKKeySize and ZSKKeySize are the sizes of RSA's two keys, in bits
	KSKKeySize, ZSKKeySize int
	// PEMKSKPrivateKey and PEMZSKPrivateKey are keys to sign with in place
	// of ones the server makes, each a private key in PEM
	PEMKSKPrivateKey, PEMZSKPrivateKey string
	// DNSKeyTTL is the TTL of the zone's DNSKEY records, 0 for the server's
	// own day
	DNSKeyTTL int
	// ZSKRolloverDays is how often the zone signing key is replaced, 0 to
	// 365 where 0 is never; nil is the server's own 30
	ZSKRolloverDays *int
	// NXProof is how the zone proves a name is not in it: NSEC, which lets
	// anyone walk the zone's names, or NSEC3; "" is the server's own NSEC.
	// Iterations and SaltLength are NSEC3's
	NXProof                string
	Iterations, SaltLength int
}

// SignZone signs a primary zone with DNSSEC. The zone is not trusted by
// anyone until its DS record (see DSInfo) is at its parent.
func (c *Client) SignZone(ctx context.Context, zone string, how Signing) error {
	if zone == "" {
		return errors.New("zones/dnssec/sign: which zone")
	}
	params := url.Values{"zone": {zone}}
	if err := how.params("zones/dnssec/sign", params); err != nil {
		return err
	}
	if how.Algorithm == AlgorithmRSA && (how.KSKKeySize == 0 || how.ZSKKeySize == 0) && (how.PEMKSKPrivateKey == "" || how.PEMZSKPrivateKey == "") {
		return errors.New("zones/dnssec/sign: RSA takes a size for each key it is to make: 2048 for the key signing key and 1024 or more for the zone signing key")
	}
	set(params, map[string]string{"pemKskPrivateKey": how.PEMKSKPrivateKey, "pemZskPrivateKey": how.PEMZSKPrivateKey, "nxProof": how.NXProof})
	for name, n := range map[string]int{"kskKeySize": how.KSKKeySize, "zskKeySize": how.ZSKKeySize, "dnsKeyTtl": how.DNSKeyTTL} {
		if n != 0 {
			params.Set(name, strconv.Itoa(n))
		}
	}
	if how.ZSKRolloverDays != nil {
		params.Set("zskRolloverDays", strconv.Itoa(*how.ZSKRolloverDays))
	}
	if how.NXProof == ProofNSEC3 {
		params.Set("iterations", strconv.Itoa(how.Iterations))
		params.Set("saltLength", strconv.Itoa(how.SaltLength))
	}

	return c.write(ctx, "zones/dnssec/sign", params, nil)
}

// UnsignZone takes DNSSEC off a primary zone. A zone whose DS record is
// still at its parent stops resolving for everyone who validates.
func (c *Client) UnsignZone(ctx context.Context, zone string) error {
	if zone == "" {
		return errors.New("zones/dnssec/unsign: which zone")
	}

	return c.write(ctx, "zones/dnssec/unsign", url.Values{"zone": {zone}}, nil)
}

// DSRecord is what a signed zone's parent is given for one of its key
// signing keys.
type DSRecord struct {
	KeyTag int `json:"keyTag"`
	// DNSKeyState is how far the key has come: Published, Ready, Active;
	// and DNSKeyStateReadyBy when a published one will be ready, in UTC
	DNSKeyState        string `json:"dnsKeyState"`
	DNSKeyStateReadyBy string `json:"dnsKeyStateReadyBy"`
	Algorithm          string `json:"algorithm"`
	PublicKey          string `json:"publicKey"`
	Digests            []struct {
		DigestType string `json:"digestType"`
		Digest     string `json:"digest"`
	} `json:"digests"`
}

// DSInfo is a signed zone with what its parent needs.
type DSInfo struct {
	Name         string     `json:"name"`
	Type         string     `json:"type"`
	DNSSECStatus string     `json:"dnssecStatus"`
	DSRecords    []DSRecord `json:"dsRecords"`
}

// DSInfo reads the DS records a signed primary zone's parent is to hold.
func (c *Client) DSInfo(ctx context.Context, zone string) (*DSInfo, error) {
	if zone == "" {
		return nil, errors.New("zones/dnssec/viewDS: which zone")
	}

	var out DSInfo
	if err := c.read(ctx, "zones/dnssec/viewDS", url.Values{"zone": {zone}}, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// SigningKey is one of a signed zone's private keys, by what the server
// says of it: the key itself is never read.
type SigningKey struct {
	KeyTag int `json:"keyTag"`
	// KeyType is KeySigningKey or ZoneSigningKey
	KeyType   string `json:"keyType"`
	Algorithm string `json:"algorithm"`
	// State is how far the key has come: Generated, Published, Ready,
	// Active, Retired, Revoked; with when it last changed and, for one on
	// its way, when it will be ready, in UTC
	State          string `json:"state"`
	StateChangedOn string `json:"stateChangedOn"`
	StateReadyBy   string `json:"stateReadyBy"`
	IsRetiring     bool   `json:"isRetiring"`
	// RolloverDays is how often the key is replaced by itself, 0 for never
	RolloverDays int `json:"rolloverDays"`
}

// DNSSEC is how a primary zone is signed.
type DNSSEC struct {
	Name         string       `json:"name"`
	Type         string       `json:"type"`
	Disabled     bool         `json:"disabled"`
	DNSSECStatus string       `json:"dnssecStatus"`
	DNSKeyTTL    int          `json:"dnsKeyTtl"`
	Keys         []SigningKey `json:"dnssecPrivateKeys"`
}

// DNSSEC reads how a signed primary zone is signed, and its keys.
func (c *Client) DNSSEC(ctx context.Context, zone string) (*DNSSEC, error) {
	if zone == "" {
		return nil, errors.New("zones/dnssec/properties/get: which zone")
	}

	var out DNSSEC
	if err := c.read(ctx, "zones/dnssec/properties/get", url.Values{"zone": {zone}}, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// ConvertToNSEC has a signed zone prove a name is not in it with NSEC, where
// it used NSEC3.
func (c *Client) ConvertToNSEC(ctx context.Context, zone string) error {
	if zone == "" {
		return errors.New("zones/dnssec/properties/convertToNSEC: which zone")
	}

	return c.write(ctx, "zones/dnssec/properties/convertToNSEC", url.Values{"zone": {zone}}, nil)
}

// ConvertToNSEC3 has a signed zone prove a name is not in it with NSEC3,
// where it used NSEC.
func (c *Client) ConvertToNSEC3(ctx context.Context, zone string) error {
	if zone == "" {
		return errors.New("zones/dnssec/properties/convertToNSEC3: which zone")
	}

	return c.write(ctx, "zones/dnssec/properties/convertToNSEC3", url.Values{"zone": {zone}}, nil)
}

// UpdateNSEC3Params sets how many times a signed zone's NSEC3 hashes a name
// and how long its salt is, in bytes.
func (c *Client) UpdateNSEC3Params(ctx context.Context, zone string, iterations, saltLength int) error {
	if zone == "" {
		return errors.New("zones/dnssec/properties/updateNSEC3Params: which zone")
	}
	if iterations < 0 || saltLength < 0 {
		return errors.New("zones/dnssec/properties/updateNSEC3Params: neither the iterations nor the salt's length can be less than none")
	}

	return c.write(ctx, "zones/dnssec/properties/updateNSEC3Params", url.Values{"zone": {zone}, "iterations": {strconv.Itoa(iterations)}, "saltLength": {strconv.Itoa(saltLength)}}, nil)
}

// UpdateDNSKeyTTL sets the TTL of a signed zone's DNSKEY records, which the
// server allows only while every key is ready or active.
func (c *Client) UpdateDNSKeyTTL(ctx context.Context, zone string, ttl int) error {
	if zone == "" || ttl <= 0 {
		return errors.New("zones/dnssec/properties/updateDnsKeyTtl: which zone, and a TTL in seconds")
	}

	return c.write(ctx, "zones/dnssec/properties/updateDnsKeyTtl", url.Values{"zone": {zone}, "ttl": {strconv.Itoa(ttl)}}, nil)
}

// NewSigningKey is a private key to add to a signed zone.
type NewSigningKey struct {
	KeyOptions

	// KeyType is KeySigningKey or ZoneSigningKey
	KeyType string
	// KeySize is RSA's, in bits
	KeySize int
	// PEMPrivateKey is a key to add in place of one the server makes, a
	// private key in PEM
	PEMPrivateKey string
	// RolloverDays is how often the key is replaced by itself, 0 to 365
	// where 0 is never; nil is the server's own 90 for a zone signing key
	// and never for a key signing key
	RolloverDays *int
}

// AddSigningKey adds a private key to a signed zone. It is only generated:
// PublishSigningKeys puts it in the zone.
func (c *Client) AddSigningKey(ctx context.Context, zone string, key NewSigningKey) error {
	if zone == "" || key.KeyType == "" {
		return errors.New("zones/dnssec/properties/addPrivateKey: which zone, and a KeySigningKey or a ZoneSigningKey")
	}
	params := url.Values{"zone": {zone}, "keyType": {key.KeyType}}
	if err := key.params("zones/dnssec/properties/addPrivateKey", params); err != nil {
		return err
	}
	if key.Algorithm == AlgorithmRSA && key.KeySize == 0 && key.PEMPrivateKey == "" {
		return errors.New("zones/dnssec/properties/addPrivateKey: RSA takes the size of the key to make, in bits")
	}
	set(params, map[string]string{"pemPrivateKey": key.PEMPrivateKey})
	if key.KeySize != 0 {
		params.Set("keySize", strconv.Itoa(key.KeySize))
	}
	if key.RolloverDays != nil {
		params.Set("rolloverDays", strconv.Itoa(*key.RolloverDays))
	}

	return c.write(ctx, "zones/dnssec/properties/addPrivateKey", params, nil)
}

// keyParams are the parameters of a call made of a single key, by its tag.
func keyParams(path, zone string, keyTag int) (url.Values, error) {
	if zone == "" || keyTag <= 0 {
		return nil, errors.New(path + ": which zone, and which key by its tag")
	}

	return url.Values{"zone": {zone}, "keyTag": {strconv.Itoa(keyTag)}}, nil
}

// UpdateSigningKey sets how often one of a signed zone's keys is replaced by
// itself, in days: 0 to 365, where 0 is never.
func (c *Client) UpdateSigningKey(ctx context.Context, zone string, keyTag, rolloverDays int) error {
	params, err := keyParams("zones/dnssec/properties/updatePrivateKey", zone, keyTag)
	if err != nil {
		return err
	}
	if rolloverDays < 0 || rolloverDays > 365 {
		return errors.New("zones/dnssec/properties/updatePrivateKey: a key is replaced every 1 to 365 days, or never with 0")
	}
	params.Set("rolloverDays", strconv.Itoa(rolloverDays))

	return c.write(ctx, "zones/dnssec/properties/updatePrivateKey", params, nil)
}

// DeleteSigningKey deletes a private key that was only generated: one that
// has been published is retired instead.
func (c *Client) DeleteSigningKey(ctx context.Context, zone string, keyTag int) error {
	params, err := keyParams("zones/dnssec/properties/deletePrivateKey", zone, keyTag)
	if err != nil {
		return err
	}

	return c.write(ctx, "zones/dnssec/properties/deletePrivateKey", params, nil)
}

// PublishSigningKeys puts every key that was only generated into the zone
// as a DNSKEY record, after which the server brings each into use by
// itself. A key signing key waits at Ready for its DS record to be at the
// zone's parent.
func (c *Client) PublishSigningKeys(ctx context.Context, zone string) error {
	if zone == "" {
		return errors.New("zones/dnssec/properties/publishAllPrivateKeys: which zone")
	}

	return c.write(ctx, "zones/dnssec/properties/publishAllPrivateKeys", url.Values{"zone": {zone}}, nil)
}

// RolloverDNSKey replaces one of a signed zone's keys: a new one is made and
// published, and the old one retired once the new is in use.
func (c *Client) RolloverDNSKey(ctx context.Context, zone string, keyTag int) error {
	params, err := keyParams("zones/dnssec/properties/rolloverDnsKey", zone, keyTag)
	if err != nil {
		return err
	}

	return c.write(ctx, "zones/dnssec/properties/rolloverDnsKey", params, nil)
}

// RetireDNSKey retires one of a signed zone's keys and takes it out of the
// zone once that is safe, which needs another key of its kind in use.
func (c *Client) RetireDNSKey(ctx context.Context, zone string, keyTag int) error {
	params, err := keyParams("zones/dnssec/properties/retireDnsKey", zone, keyTag)
	if err != nil {
		return err
	}

	return c.write(ctx, "zones/dnssec/properties/retireDnsKey", params, nil)
}
