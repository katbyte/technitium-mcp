package technitium

import (
	"context"
	"errors"
	"net/url"
)

// CatalogZones lists the catalog zones the server holds, by name.
func (c *Client) CatalogZones(ctx context.Context) ([]string, error) {
	var out struct {
		Names []string `json:"catalogZoneNames"`
	}
	if err := c.read(ctx, "zones/catalogs/list", nil, &out); err != nil {
		return nil, err
	}

	return out.Names, nil
}

// ZoneImport is how a zone file is taken into a zone.
type ZoneImport struct {
	// KeepExisting leaves a name's records of a type as they are where the
	// file has records for them too; without it the file's replace them
	KeepExisting bool
	// ReplaceZone deletes every record the zone has before the file's are
	// added
	ReplaceZone bool
	// OverwriteSOASerial takes the SOA serial the file gives. A serial lower
	// than the zone's own stops its copies from following it
	OverwriteSOASerial bool
}

// ImportZone adds the records of a zone file, as ExportZone gives one, to a
// zone the server holds.
func (c *Client) ImportZone(ctx context.Context, zone, zoneFile string, how ZoneImport) error {
	if zone == "" {
		return errors.New("zones/import: which zone")
	}
	params := url.Values{"zone": {zone}}
	if how.KeepExisting {
		params.Set("overwrite", "false")
	}
	if how.ReplaceZone {
		params.Set("overwriteZone", yes)
	}
	if how.OverwriteSOASerial {
		params.Set("overwriteSoaSerial", yes)
	}

	return c.upload(ctx, "zones/import", params, file{name: zone + ".zone", data: []byte(zoneFile)}, nil)
}

// CloneZone makes a zone that is another's copy at the time: every record
// the source has, under the new name.
func (c *Client) CloneZone(ctx context.Context, zone, source string) error {
	if zone == "" || source == "" {
		return errors.New("zones/clone: a zone is cloned from a source zone, under a name of its own")
	}

	return c.write(ctx, "zones/clone", url.Values{"zone": {zone}, "sourceZone": {source}}, nil)
}

// ConvertZone changes what type a zone is: a secondary into a primary, a
// primary into a forwarder, and the other conversions the server allows.
func (c *Client) ConvertZone(ctx context.Context, zone, toType string) error {
	if zone == "" || toType == "" {
		return errors.New("zones/convert: which zone, and the type it is to be")
	}

	return c.write(ctx, "zones/convert", url.Values{"zone": {zone}, "type": {toType}}, nil)
}

// EnableZone switches a zone back on.
func (c *Client) EnableZone(ctx context.Context, zone string) error {
	if zone == "" {
		return errors.New("zones/enable: which zone")
	}

	return c.write(ctx, "zones/enable", url.Values{"zone": {zone}}, nil)
}

// DisableZone switches a zone off: the server keeps it and answers nothing
// from it.
func (c *Client) DisableZone(ctx context.Context, zone string) error {
	if zone == "" {
		return errors.New("zones/disable: which zone")
	}

	return c.write(ctx, "zones/disable", url.Values{"zone": {zone}}, nil)
}
