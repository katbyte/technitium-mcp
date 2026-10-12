package tools

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/katbyte/technitium-mcp/lib/servers"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// settingText is a setting's value as the API takes one back: a list with
// commas between, and anything else as it is written.
func settingText(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case []any:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			parts = append(parts, settingText(item))
		}

		return strings.Join(parts, ",")
	case map[string]any:
		raw, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprint(v)
		}

		return string(raw)
	default:
		raw, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprint(v)
		}

		return string(raw)
	}
}

// backupParts are the parts of a server a backup holds, by the name a tool
// takes each under.
var backupParts = map[string]func(items *technitium.BackupItems){
	"accounts":      func(items *technitium.BackupItems) { items.AuthConfig = true },
	"cluster":       func(items *technitium.BackupItems) { items.ClusterConfig = true },
	"web_service":   func(items *technitium.BackupItems) { items.WebServiceSettings = true },
	"dns_settings":  func(items *technitium.BackupItems) { items.DNSSettings = true },
	"log_settings":  func(items *technitium.BackupItems) { items.LogSettings = true },
	"zones":         func(items *technitium.BackupItems) { items.Zones = true },
	"allowed_names": func(items *technitium.BackupItems) { items.AllowedZones = true },
	"blocked_names": func(items *technitium.BackupItems) { items.BlockedZones = true },
	"block_lists":   func(items *technitium.BackupItems) { items.BlockLists = true },
	"apps":          func(items *technitium.BackupItems) { items.Apps = true },
	"dhcp":          func(items *technitium.BackupItems) { items.Scopes = true },
	"stats":         func(items *technitium.BackupItems) { items.Stats = true },
	"logs":          func(items *technitium.BackupItems) { items.Logs = true },
}

// partNames are the names of the parts, in the order a person thinks of
// them.
var partNames = []string{"zones", "dns_settings", "dhcp", "allowed_names", "blocked_names", "block_lists", "apps", "accounts", "web_service", "cluster", "log_settings", "stats", "logs"}

// partsOf reads the parts a tool was asked for; "all" is every one.
func partsOf(asked []string) (technitium.BackupItems, []string, error) {
	var items technitium.BackupItems
	var names []string
	for _, part := range asked {
		part = strings.ToLower(strings.TrimSpace(part))
		switch {
		case part == "":
		case part == "all":
			return technitium.Everything(), slices.Clone(partNames), nil
		case backupParts[part] == nil:
			return items, nil, fmt.Errorf("part %q: a backup's parts are %s, or all", part, strings.Join(partNames, ", "))
		case !slices.Contains(names, part):
			backupParts[part](&items)
			names = append(names, part)
		default:
		}
	}
	if len(names) == 0 {
		return items, nil, fmt.Errorf("which parts of the server: give some of %s, or all", strings.Join(partNames, ", "))
	}

	return items, names, nil
}

// zipEntries lists what a zip file holds, by name and size.
func zipEntries(data []byte) ([]string, error) {
	archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	entries := []string{}
	for _, f := range archive.File {
		entries = append(entries, fmt.Sprintf("%s (%d bytes)", f.Name, f.UncompressedSize64))
	}

	return entries, nil
}

// restoreBreaksVersion is the one version of the server known to fail when a backup's zones are put back and one of them is a zone it does not
// hold: it answers with an error, and then will not start again. 15.6.0 does not, and nor does 15.6.1 when the accounts are restored with the zones.
const restoreBreaksVersion = "15.6.1"

// restoreWouldStopTheServer refuses a restore of zones that would leave the server unable to start, naming the zones and the two ways round it.
func restoreWouldStopTheServer(ctx context.Context, srv *servers.Server, backup []byte) error {
	inBackup := zonesInBackup(backup)
	if len(inBackup) == 0 {
		return nil
	}

	settings, err := srv.Client.AllSettings(ctx)
	if err != nil {
		return fmt.Errorf("reading %s's version before restoring zones onto it: %w", srv.Name, err)
	}
	if fmt.Sprint(settings["version"]) != restoreBreaksVersion {
		return nil
	}

	held, err := srv.Client.Zones(ctx, technitium.ZoneFilter{})
	if err != nil {
		return fmt.Errorf("reading the zones %s holds before restoring zones onto it: %w", srv.Name, err)
	}
	missing := slices.DeleteFunc(inBackup, func(zone string) bool {
		return slices.ContainsFunc(held, func(z technitium.Zone) bool { return strings.EqualFold(z.Name, zone) })
	})
	if len(missing) == 0 {
		return nil
	}

	return fmt.Errorf("%s runs version %s of the server, which fails when a zone it does not hold is put back without the accounts: it answers with an error and then will not start again. The backup has %s, which %s does not hold. Make each as an empty zone first (zone_create) and restore again, or restore accounts with zones, which replaces every account and token. Nothing was changed", srv.Name, restoreBreaksVersion, strings.Join(missing, ", "), srv.Name)
}

// zonesInBackup is the zones a backup holds a file for, by name.
func zonesInBackup(data []byte) []string {
	archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil
	}

	zones := []string{}
	for _, f := range archive.File {
		if name, ok := strings.CutPrefix(f.Name, "zones/"); ok && strings.HasSuffix(name, ".zone") {
			zones = append(zones, strings.TrimSuffix(name, ".zone"))
		}
	}

	return zones
}

func registerMaintainTools(r *registry) {
	type settingRow struct {
		Name   string         `json:"name"             jsonschema:"the setting, by the name the server's API knows it under, which is the name settings_set takes"`
		Value  any            `json:"value,omitempty"  jsonschema:"its value, when every server asked has the same"`
		Values map[string]any `json:"values,omitempty" jsonschema:"its value on each server, when they differ"`
	}
	type settingsGetIn struct {
		serverArg

		Name       string `json:"name,omitempty"        jsonschema:"only the settings whose name matches: text anywhere in the name, or with a * the whole name, as cache*, *Ttl or webService*"`
		DifferOnly bool   `json:"differ_only,omitempty" jsonschema:"only the settings the servers asked do not have alike"`
	}
	type settingsGetOut struct {
		Settings []settingRow    `json:"settings"`
		Differ   int             `json:"differ"           jsonschema:"how many of the settings matched are not the same on every server asked"`
		Failed   []serverFailure `json:"failed,omitempty"`
		Note     string          `json:"note,omitempty"`
	}
	add(r, readTool, &mcp.Tool{
		Name:        "settings_get",
		Description: "Every setting a server has, by the name its API gives it, with the value on each server set side by side where they differ: the hundred and thirty or so behind the web console's Settings pages, from the recursion policy and the forwarders to cache sizes, timeouts, the optional protocols and logging. server_settings gives the ones that matter most with what each means; this is all of them, raw, and is where the name settings_set takes is found. Filter by name. Nothing secret is given: no password, and a transfer key by its name and algorithm only.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in settingsGetIn) (*mcp.CallToolResult, settingsGetOut, error) {
		picked, err := r.servers.Pick(in.Server)
		if err != nil {
			return nil, settingsGetOut{}, err
		}
		answers := ask(ctx, picked, func(ctx context.Context, srv *servers.Server) (map[string]any, error) {
			return srv.Client.AllSettings(ctx)
		})
		failed, err := failures(answers)
		if err != nil {
			return nil, settingsGetOut{}, err
		}

		filter := newPattern(in.Name)
		names := map[string]bool{}
		for _, a := range answers {
			for name := range a.Value {
				if filter.matches(name) {
					names[name] = true
				}
			}
		}
		out := settingsGetOut{Settings: []settingRow{}, Failed: failed}
		for _, name := range slices.Sorted(maps.Keys(names)) {
			row := settingRow{Name: name, Values: map[string]any{}}
			var first string
			differ, seen := false, false
			for _, a := range answers {
				if a.Err != nil {
					continue
				}
				value := a.Value[name]
				row.Values[a.Server.Name] = value
				if text := settingText(value); !seen {
					first, seen = text, true
				} else if text != first {
					differ = true
				}
			}
			if differ {
				out.Differ++
			} else {
				if in.DifferOnly {
					continue
				}
				for _, value := range row.Values {
					row.Value = value
				}
				row.Values = nil
			}
			out.Settings = append(out.Settings, row)
		}
		if len(out.Settings) == 0 {
			out.Note = "no setting matched: leave name out to see them all"
		}

		return nil, out, nil
	})

	type settingsSetIn struct {
		writeServerArg

		Settings map[string]string `json:"settings"          jsonschema:"each setting to change, by the name settings_get gives it, with its new value written as text: true or false, a number, or a list with commas between its entries, as forwarders 9.9.9.9,1.1.1.1. A list is cleared with false"`
		DryRun   bool              `json:"dry_run,omitempty" jsonschema:"change nothing, and answer with what would be"`
	}
	type settingsSetOut struct {
		Server  string         `json:"server"`
		Changed bool           `json:"changed"`
		Changes []string       `json:"changes"         jsonschema:"each setting changed, with what it was; with a dry run, each that would be"`
		After   map[string]any `json:"after,omitempty" jsonschema:"the settings named, as the server has them now, read back; absent from a dry run"`
		Note    string         `json:"note,omitempty"`
	}
	add(r, writeTool, &mcp.Tool{
		Name:        "settings_set",
		Description: "Change settings on one server, by the names settings_get gives them: any of the hundred and thirty or so the server has. Only the settings named change, and a name the server does not know is refused rather than passed over. Some take effect by restarting part of the server - the web console's own address, port and HTTPS, and the optional protocols - and changing where the console answers can leave this tool unable to reach it until it is configured with the new address. A password is set and never read back. Transfer keys have a tool of their own (tsig_key_set), which keeps the keys not named, and blocking is better switched with the tools for it, which say what a change does. On a cluster most settings are the primary's to change and reach every node.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in settingsSetIn) (*mcp.CallToolResult, settingsSetOut, error) {
		if len(in.Settings) == 0 {
			return nil, settingsSetOut{}, errors.New("which settings: give each by the name settings_get gives it, with its new value")
		}
		want := map[string]string{}
		for name, value := range in.Settings {
			name = strings.TrimSpace(name)
			i := slices.IndexFunc(technitium.SettingNames, func(known string) bool { return strings.EqualFold(known, name) })
			switch {
			case i < 0:
				return nil, settingsSetOut{}, fmt.Errorf("there is no setting named %q: settings_get lists them, and takes a pattern to find one by", name)
			case technitium.SettingNames[i] == "tsigKeys":
				return nil, settingsSetOut{}, errors.New("the transfer keys are set as one list with their secrets, which are never read back: tsig_key_set adds or changes one and tsig_key_delete takes one away, leaving the rest as they are")
			default:
				want[technitium.SettingNames[i]] = strings.TrimSpace(value)
			}
		}
		srv, err := r.servers.One(in.Server)
		if err != nil {
			return nil, settingsSetOut{}, err
		}
		before, err := srv.Client.AllSettings(ctx)
		if err != nil {
			return nil, settingsSetOut{}, fmt.Errorf("%s: %w", srv.Name, err)
		}

		out := settingsSetOut{Server: srv.Name, Changes: []string{}}
		done := &changes{dry: in.DryRun}
		change := map[string]string{}
		restarts := false
		for _, name := range slices.Sorted(maps.Keys(want)) {
			value := want[name]
			was, readable := before[name]
			switch {
			case !readable && !slices.Contains(technitium.SettingsNeverRead, name):
				return nil, settingsSetOut{}, fmt.Errorf("%s runs version %v of the server, which has no setting named %s: a later version brought it, and this one would say ok and pass it over. Nothing was changed", srv.Name, before["version"], name)
			case !readable:
				// a password, or the proxy, which the server gives back as one thing: set as asked, with nothing to compare
				change[name] = value
				done.did("set %s on %s", name, srv.Name)
			case settingText(was) == value || (value == "false" && settingText(was) == ""):
				continue
			default:
				change[name] = value
				done.did("set %s on %s from %q to %q", name, srv.Name, settingText(was), value)
			}
			if strings.HasPrefix(name, "webService") || strings.HasPrefix(name, "enableDnsOver") || strings.HasPrefix(name, "dnsOver") || name == "dnsServerLocalEndPoints" {
				restarts = true
			}
		}
		out.Changed = len(change) > 0
		if out.Changed {
			out.Changes = done.said
		}
		if restarts {
			out.Note = "a setting among these restarts part of the server, which for a moment answers nothing; one that changes where the console answers leaves this tool configured with the old address"
		}
		if out.Changed && !in.DryRun {
			after, err := srv.Client.SetSettings(ctx, change)
			if err != nil {
				return nil, settingsSetOut{}, fmt.Errorf("setting them: %w", err)
			}
			out.After = map[string]any{}
			var lost []string
			for name, value := range change {
				now, readable := after[name]
				if !readable {
					continue
				}
				out.After[name] = now
				if settingText(now) != value && (value != "false" || settingText(now) != "") {
					lost = append(lost, fmt.Sprintf("%s is %q", name, settingText(now)))
				}
			}
			if len(lost) > 0 {
				slices.Sort(lost)
				out.Note = strings.TrimSpace("the server said ok and does not have every value as it was written: " + strings.Join(lost, "; ") + ". A value it cannot take it passes over or rewrites in its own form. " + out.Note)
			}
		}

		return nil, out, nil
	})

	type tsigKeySetIn struct {
		writeServerArg

		Name         string `json:"name"                    jsonschema:"the key's name, a domain name by custom, as transfer.example.com: both ends of a transfer know the key by it"`
		SharedSecret string `json:"shared_secret,omitempty" jsonschema:"the key's secret in base64, which the other end must be given too. Left out, the server makes one up, which then has to be read from its web console to give the other end"`
		Algorithm    string `json:"algorithm,omitempty"     jsonschema:"hmac-sha256 (the default), hmac-sha384, hmac-sha512 and the older ones the server takes"`
		DryRun       bool   `json:"dry_run,omitempty"       jsonschema:"change nothing, and answer with what would be"`
	}
	type tsigKeyOut struct {
		Server  string   `json:"server"`
		Changed bool     `json:"changed"`
		Changes []string `json:"changes"`
		Keys    []string `json:"keys"           jsonschema:"the transfer keys the server has now, by name; with a dry run, the ones it has"`
		Note    string   `json:"note,omitempty"`
	}
	add(r, writeTool, &mcp.Tool{
		Name:        "tsig_key_set",
		Description: "Add a transfer key (TSIG) to a server, or change the one it has under the name, leaving its other keys as they are. A key is a secret two servers share, so that one will transfer a zone to the other, or take updates from it, and to nobody else: a zone then names the key in its options (zone_get shows which it uses). The secret is never read back. On a cluster the keys are the primary's to change.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in tsigKeySetIn) (*mcp.CallToolResult, tsigKeyOut, error) {
		name := cleanName(in.Name)
		if name == "" || strings.ContainsAny(name, " |") {
			return nil, tsigKeyOut{}, errors.New("which key: give its name, a domain name by custom, as transfer.example.com")
		}
		srv, err := r.servers.One(in.Server)
		if err != nil {
			return nil, tsigKeyOut{}, err
		}
		keys, err := srv.Client.TSIGKeyNames(ctx)
		if err != nil {
			return nil, tsigKeyOut{}, fmt.Errorf("%s: %w", srv.Name, err)
		}
		algorithm := strings.ToLower(strings.TrimSpace(in.Algorithm))
		if algorithm == "" {
			algorithm = technitium.DefaultTSIGAlgorithm
		}

		out := tsigKeyOut{Server: srv.Name, Changed: true, Keys: keys}
		done := &changes{dry: in.DryRun}
		verb := "added the transfer key %s (%s) to %s"
		if slices.ContainsFunc(keys, func(k string) bool { return sameName(k, name) }) {
			verb = "changed the transfer key %s (%s) on %s"
		}
		if strings.TrimSpace(in.SharedSecret) == "" {
			out.Note = "the server made the key's secret up: it is read from the web console's Settings, TSIG, to give the other end"
		}
		if done.did(verb, name, algorithm, srv.Name) {
			if err := srv.Client.SetTSIGKey(ctx, name, strings.TrimSpace(in.SharedSecret), algorithm); err != nil {
				return nil, tsigKeyOut{}, fmt.Errorf("setting the key: %w", err)
			}
			if out.Keys, err = srv.Client.TSIGKeyNames(ctx); err != nil {
				return nil, tsigKeyOut{}, fmt.Errorf("the key was set and the keys could not be read back: %w", err)
			}
			if !slices.ContainsFunc(out.Keys, func(k string) bool { return sameName(k, name) }) {
				return nil, tsigKeyOut{}, fmt.Errorf("the server said ok and %s has no key named %s", srv.Name, name)
			}
		}
		out.Changes = done.said
		if out.Keys == nil {
			out.Keys = []string{}
		}

		return nil, out, nil
	})

	type tsigKeyDeleteIn struct {
		writeServerArg

		Name   string `json:"name"              jsonschema:"the key's name, as settings_get gives it under tsigKeys"`
		DryRun bool   `json:"dry_run,omitempty" jsonschema:"delete nothing, and answer with what would be"`
	}
	add(r, deleteTool, &mcp.Tool{
		Name:        "tsig_key_delete",
		Description: "Take a transfer key (TSIG) off a server, leaving its other keys as they are. A zone that named the key can no longer be transferred or updated with it, so look at which zones use it first (zone_get). The key a cluster transfers its own catalog with is the server's to keep, and it refuses to lose it.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in tsigKeyDeleteIn) (*mcp.CallToolResult, tsigKeyOut, error) {
		name := cleanName(in.Name)
		if name == "" {
			return nil, tsigKeyOut{}, errors.New("which key: give its name")
		}
		srv, err := r.servers.One(in.Server)
		if err != nil {
			return nil, tsigKeyOut{}, err
		}
		keys, err := srv.Client.TSIGKeyNames(ctx)
		if err != nil {
			return nil, tsigKeyOut{}, fmt.Errorf("%s: %w", srv.Name, err)
		}
		out := tsigKeyOut{Server: srv.Name, Keys: keys, Changes: []string{}}
		if out.Keys == nil {
			out.Keys = []string{}
		}
		if !slices.ContainsFunc(keys, func(k string) bool { return sameName(k, name) }) {
			out.Note = "the server has no key by that name: there is nothing to take away"

			return nil, out, nil
		}

		out.Changed = true
		done := &changes{dry: in.DryRun}
		if done.did("removed the transfer key %s from %s", name, srv.Name) {
			if err := srv.Client.DeleteTSIGKey(ctx, name); err != nil {
				return nil, tsigKeyOut{}, fmt.Errorf("taking the key away: %w", err)
			}
			if out.Keys, err = srv.Client.TSIGKeyNames(ctx); err != nil {
				return nil, tsigKeyOut{}, fmt.Errorf("the key was taken away and the keys could not be read back: %w", err)
			}
			if out.Keys == nil {
				out.Keys = []string{}
			}
		}
		out.Changes = done.said

		return nil, out, nil
	})

	type backupIn struct {
		writeServerArg

		Path  string   `json:"path"  jsonschema:"where to write the backup, on the machine this tool runs on: a folder, in which the file is named for the server and the time, or a file name ending .zip. A file that is there already is not written over"`
		Parts []string `json:"parts" jsonschema:"what to back up: all, or any of zones, dns_settings, dhcp, allowed_names, blocked_names, block_lists, apps, accounts, web_service, cluster, log_settings, stats, logs"`
	}
	type backupOut struct {
		Server string   `json:"server"`
		Path   string   `json:"path"   jsonschema:"the file written"`
		Bytes  int      `json:"bytes"`
		Parts  []string `json:"parts"  jsonschema:"the parts asked for"`
		Files  []string `json:"files"  jsonschema:"what the backup holds, each file with its size"`
		Note   string   `json:"note"`
	}
	add(r, readTool, &mcp.Tool{
		Name:        "settings_backup",
		Description: "Write a backup of one server to a zip file on the machine this tool runs on: the parts asked for, or all of it - zones, settings, DHCP scopes, the allowed and blocked names, apps, accounts and tokens, statistics and logs. settings_restore puts parts of one back. The server is only read. A backup with accounts, settings or zones in it holds what is secret on the server - password hashes, tokens, transfer and signing keys - so the file is written readable by its owner alone and is to be kept as carefully as those. A backup is of what the server has written to disk, which lags a change by a few seconds: one taken straight after a change can miss it.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in backupIn) (*mcp.CallToolResult, backupOut, error) {
		items, parts, err := partsOf(in.Parts)
		if err != nil {
			return nil, backupOut{}, err
		}
		srv, err := r.servers.One(in.Server)
		if err != nil {
			return nil, backupOut{}, err
		}
		path := strings.TrimSpace(in.Path)
		if path == "" {
			return nil, backupOut{}, errors.New("where to write the backup: give a folder, or a file name ending .zip")
		}
		if info, statErr := os.Stat(path); statErr == nil && info.IsDir() {
			path = filepath.Join(path, fmt.Sprintf("technitium-%s-%s.zip", srv.Name, time.Now().UTC().Format("20060102T150405Z")))
		} else if !strings.HasSuffix(strings.ToLower(path), ".zip") {
			return nil, backupOut{}, fmt.Errorf("%s is no folder that is there, and a file is named ending .zip", path)
		}
		data, err := srv.Client.Backup(ctx, items)
		if err != nil {
			return nil, backupOut{}, fmt.Errorf("backing up %s: %w", srv.Name, err)
		}
		files, err := zipEntries(data)
		if err != nil {
			return nil, backupOut{}, fmt.Errorf("%s answered with something that is no zip file: %w", srv.Name, err)
		}
		// never over a file that is there, and for its owner's eyes only: the backup holds the server's secrets
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: the path is where the operator asked for the backup to be written
		if err != nil {
			return nil, backupOut{}, fmt.Errorf("writing the backup: %w", err)
		}
		if _, err := file.Write(data); err != nil {
			_ = file.Close()

			return nil, backupOut{}, fmt.Errorf("writing the backup: %w", err)
		}
		if err := file.Close(); err != nil {
			return nil, backupOut{}, fmt.Errorf("writing the backup: %w", err)
		}

		return nil, backupOut{Server: srv.Name, Path: path, Bytes: len(data), Parts: parts, Files: files, Note: "the file holds whatever is secret in the parts backed up, and is readable by its owner alone: keep it so"}, nil
	})

	type restoreIn struct {
		writeServerArg

		Path           string   `json:"path"                      jsonschema:"the backup to restore from, a zip file on the machine this tool runs on, as settings_backup wrote one"`
		Parts          []string `json:"parts"                     jsonschema:"what to put back from it: all, or any of zones, dns_settings, dhcp, allowed_names, blocked_names, block_lists, apps, accounts, web_service, cluster, log_settings, stats, logs"`
		DeleteExisting bool     `json:"delete_existing,omitempty" jsonschema:"for each part restored, also delete what the server has of it that the backup has not: without it a zone made since the backup stays, and with it the zone goes"`
		DryRun         bool     `json:"dry_run,omitempty"         jsonschema:"change nothing, and answer with what the backup holds"`
	}
	type restoreOut struct {
		Server  string   `json:"server"`
		Changed bool     `json:"changed"`
		Changes []string `json:"changes"`
		Files   []string `json:"files"          jsonschema:"what the backup holds, each file with its size"`
		Note    string   `json:"note,omitempty"`
	}
	add(r, deleteTool, &mcp.Tool{
		Name:        "settings_restore",
		Description: "Put parts of a server back from a backup's zip file, writing over what the server has of each: there is no undo, so take a backup of the server as it is first (settings_backup). Only the parts named are touched. Restoring the accounts replaces every account and token, which can end the token this tool works under; restoring web_service can move the console. A backup from one server restored onto another makes the second a copy of the first in those parts, its name and keys included. With dry_run it changes nothing and lists what the backup holds. Version 15.6.1 of the server fails, and then will not start again, when a zone it does not hold is put back without the accounts: that restore is refused, with the two ways round it.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in restoreIn) (*mcp.CallToolResult, restoreOut, error) {
		items, parts, err := partsOf(in.Parts)
		if err != nil {
			return nil, restoreOut{}, err
		}
		srv, err := r.servers.One(in.Server)
		if err != nil {
			return nil, restoreOut{}, err
		}
		data, err := os.ReadFile(strings.TrimSpace(in.Path))
		if err != nil {
			return nil, restoreOut{}, fmt.Errorf("reading the backup: %w", err)
		}
		files, err := zipEntries(data)
		if err != nil {
			return nil, restoreOut{}, fmt.Errorf("%s is no zip file, which is what a backup is: %w", in.Path, err)
		}

		if items.Zones && !items.AuthConfig {
			if err := restoreWouldStopTheServer(ctx, srv, data); err != nil {
				return nil, restoreOut{}, err
			}
		}

		out := restoreOut{Server: srv.Name, Changed: true, Files: files}
		done := &changes{dry: in.DryRun}
		how := "writing over what it has of them"
		if in.DeleteExisting {
			how = "writing over what it has of them and deleting what the backup has not"
		}
		if done.did("restored %s on %s from %s, %s", strings.Join(parts, ", "), srv.Name, filepath.Base(in.Path), how) {
			if _, err := srv.Client.Restore(ctx, items, in.DeleteExisting, data); err != nil {
				if technitium.IsInvalidToken(err) {
					out.Changes = done.said
					out.Note = "the backup was restored, and with it the accounts and tokens it held: the token this tool is configured with is no longer taken on the server"

					return nil, out, nil
				}

				return nil, restoreOut{}, fmt.Errorf("restoring %s: %w", srv.Name, err)
			}
		}
		out.Changes = done.said

		return nil, out, nil
	})
}
