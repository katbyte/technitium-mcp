package tools

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/katbyte/technitium-mcp/lib/servers"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// usersOf and groupsOfAccess are lists of entries as the client sets them.
func usersOf(entries []accessEntry) []technitium.UserAccess {
	out := make([]technitium.UserAccess, 0, len(entries))
	for _, e := range entries {
		out = append(out, technitium.UserAccess{Username: e.Name, CanView: e.View, CanModify: e.Modify, CanDelete: e.Delete})
	}

	return out
}

func groupsOfAccess(entries []accessEntry) []technitium.GroupAccess {
	out := make([]technitium.GroupAccess, 0, len(entries))
	for _, e := range entries {
		out = append(out, technitium.GroupAccess{Name: e.Name, CanView: e.View, CanModify: e.Modify, CanDelete: e.Delete})
	}

	return out
}

// ssoRow is how one server is set up for single sign-on.
type ssoRow struct {
	Server                 string            `json:"server"`
	Enabled                bool              `json:"enabled"`
	Authority              string            `json:"authority,omitempty"                          jsonschema:"the provider's address, as OpenID Connect calls it"`
	ClientID               string            `json:"client_id,omitempty"`
	MetadataAddress        string            `json:"metadata_address,omitempty"                   jsonschema:"where the provider describes itself, when that is not where its authority says"`
	AllowSignup            bool              `json:"allow_signup,omitempty"                       jsonschema:"an account is made here for whoever signs in through the provider for the first time"`
	AllowSignupOnlyForMaps bool              `json:"allow_signup_only_for_mapped_users,omitempty" jsonschema:"and only for those in a group at the provider that the group map names"`
	GroupMap               map[string]string `json:"group_map"                                    jsonschema:"each group at the provider with the group here its members are put in"`
	Error                  string            `json:"error,omitempty"`
}

func ssoRowOf(server string, sso *technitium.SSO) ssoRow {
	row := ssoRow{Server: server, Enabled: sso.Enabled, Authority: sso.Authority, ClientID: sso.ClientID, MetadataAddress: sso.MetadataAddress, AllowSignup: sso.AllowSignup, AllowSignupOnlyForMaps: sso.AllowSignupOnlyForMappedUsers, GroupMap: map[string]string{}}
	for _, m := range sso.GroupMap {
		row.GroupMap[m.RemoteGroup] = m.LocalGroup
	}

	return row
}

func registerAccessTools(r *registry) {
	type accessGetIn struct {
		serverArg

		Section string `json:"section,omitempty" jsonschema:"one section, by its name: Dashboard, Zones, Cache, Allowed, Blocked, Apps, DnsClient, Settings, DhcpServer, Administration or Logs. Left out, every section is given"`
		Zone    string `json:"zone,omitempty"    jsonschema:"one zone instead, as zone_list gives it: who may do what with that zone, which is beside what the Zones section gives everybody"`
	}
	type accessOn struct {
		Server      string      `json:"server"`
		Permissions []accessRow `json:"permissions"`
		Error       string      `json:"error,omitempty"`
	}
	type accessGetOut struct {
		Servers []accessOn `json:"servers" jsonschema:"each server asked, with who may do what on it"`
	}
	add(r, readTool, &mcp.Tool{
		Name:        "access_get",
		Description: "Who may do what on each server. A server is divided into sections - Zones, Settings, Logs and the rest - and each says what every group, and any account named by itself, may view, modify and delete there. An account may do what any of its groups may, plus what it is given by name. A zone has permissions of its own beside the section's: to change a zone's records an account needs the zone itself, and listing the zones shows only those it may view. Give section for one section, zone for one zone, or neither for all of the sections.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in accessGetIn) (*mcp.CallToolResult, accessGetOut, error) {
		section, zone := strings.TrimSpace(in.Section), cleanName(in.Zone)
		if section != "" && zone != "" {
			return nil, accessGetOut{}, errors.New("give a section or a zone, not both: a zone's permissions are its own")
		}
		picked, err := r.servers.Pick(in.Server)
		if err != nil {
			return nil, accessGetOut{}, err
		}
		answers := ask(ctx, picked, func(ctx context.Context, srv *servers.Server) ([]accessRow, error) {
			switch {
			case zone != "":
				got, err := srv.Client.ZonePermissions(ctx, zone, false)
				if err != nil {
					return nil, err
				}

				return []accessRow{accessRowOf(got)}, nil
			case section != "":
				got, err := srv.Client.SectionPermissions(ctx, section, false)
				if err != nil {
					return nil, err
				}

				return []accessRow{accessRowOf(got)}, nil
			default:
				all, err := srv.Client.Permissions(ctx)
				if err != nil {
					return nil, err
				}
				rows := []accessRow{}
				for i := range all {
					rows = append(rows, accessRowOf(&all[i]))
				}

				return rows, nil
			}
		})
		if _, err := failures(answers); err != nil {
			return nil, accessGetOut{}, err
		}

		out := accessGetOut{Servers: []accessOn{}}
		for _, a := range answers {
			row := accessOn{Server: a.Server.Name, Permissions: a.Value}
			if a.Err != nil {
				row.Permissions, row.Error = []accessRow{}, a.Err.Error()
			}
			out.Servers = append(out.Servers, row)
		}

		return nil, out, nil
	})

	type accessSetIn struct {
		writeServerArg

		Section      string        `json:"section,omitempty"       jsonschema:"the section to set permissions in, by its name as access_get gives it"`
		Zone         string        `json:"zone,omitempty"          jsonschema:"or the zone to set them on, as zone_list gives it"`
		Users        []accessEntry `json:"users,omitempty"         jsonschema:"accounts to give something by name, each with what it may do: one already named is changed to this, and the others are left as they are"`
		Groups       []accessEntry `json:"groups,omitempty"        jsonschema:"groups to give something, the same way"`
		RemoveUsers  []string      `json:"remove_users,omitempty"  jsonschema:"accounts to take off the list, which leaves each what its groups give it"`
		RemoveGroups []string      `json:"remove_groups,omitempty" jsonschema:"groups to take off the list"`
		DryRun       bool          `json:"dry_run,omitempty"       jsonschema:"change nothing, and answer with what would be"`
	}
	type accessSetOut struct {
		Server  string     `json:"server"`
		Changed bool       `json:"changed"`
		Changes []string   `json:"changes"`
		After   *accessRow `json:"after,omitempty" jsonschema:"the permissions as the server holds them now, read back; with a dry run, as they would be"`
	}
	add(r, writeTool, &mcp.Tool{
		Name:        "access_set",
		Description: "Change who may do what in one section of a server, or with one zone: give an account or a group view, modify and delete as wanted, change what one already has, or take one off the list. Whoever is not named in the call is left as they are. An entry with nothing allowed is kept on the list as nothing, which is not the same as taking it off. The Administrators group cannot be given less than everything in Administration here, which would lock every administrator out.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in accessSetIn) (*mcp.CallToolResult, accessSetOut, error) {
		section, zone := strings.TrimSpace(in.Section), cleanName(in.Zone)
		if (section == "") == (zone == "") {
			return nil, accessSetOut{}, errors.New("give the section or the zone the permissions are set for, one of the two")
		}
		if len(in.Users)+len(in.Groups)+len(in.RemoveUsers)+len(in.RemoveGroups) == 0 {
			return nil, accessSetOut{}, errors.New("nothing was given to change: users, groups, remove_users or remove_groups")
		}
		for _, e := range slices.Concat(in.Users, in.Groups) {
			if strings.TrimSpace(e.Name) == "" || strings.Contains(e.Name, "|") {
				return nil, accessSetOut{}, errors.New("every entry names an account or a group, by a name with no | in it")
			}
		}
		less := func(e accessEntry) bool {
			return strings.EqualFold(e.Name, "Administrators") && (!e.View || !e.Modify || !e.Delete)
		}
		gone := func(name string) bool { return strings.EqualFold(name, "Administrators") }
		if strings.EqualFold(section, "Administration") && (slices.ContainsFunc(in.Groups, less) || slices.ContainsFunc(in.RemoveGroups, gone)) {
			return nil, accessSetOut{}, errors.New("the Administrators group keeps everything in Administration: with less, nobody could change a permission again")
		}
		srv, err := r.servers.One(in.Server)
		if err != nil {
			return nil, accessSetOut{}, err
		}
		var before *technitium.Access
		if zone != "" {
			before, err = srv.Client.ZonePermissions(ctx, zone, true)
		} else {
			before, err = srv.Client.SectionPermissions(ctx, section, true)
		}
		if err != nil {
			return nil, accessSetOut{}, fmt.Errorf("%s: %w", srv.Name, err)
		}
		// a name the server does not know is refused before anything is set
		for _, e := range in.Users {
			if !slices.ContainsFunc(before.AllUsers, func(u string) bool { return strings.EqualFold(u, e.Name) }) {
				return nil, accessSetOut{}, fmt.Errorf("%s has no account named %s: user_list names the accounts", srv.Name, e.Name)
			}
		}
		for _, e := range in.Groups {
			if !slices.ContainsFunc(before.AllGroups, func(g string) bool { return strings.EqualFold(g, e.Name) }) {
				return nil, accessSetOut{}, fmt.Errorf("%s has no group named %s: group_list names the groups", srv.Name, e.Name)
			}
		}

		current := accessRowOf(before)
		users, saidUsers := accessMerged("account", current.Users, in.Users, in.RemoveUsers)
		groups, saidGroups := accessMerged("group", current.Groups, in.Groups, in.RemoveGroups)
		where := "the " + before.Section + " section"
		if zone != "" {
			where = "the zone " + before.SubItem
		}
		out := accessSetOut{Server: srv.Name, Changes: []string{}}
		done := &changes{dry: in.DryRun}
		for _, said := range slices.Concat(saidUsers, saidGroups) {
			done.did("%s, in %s on %s", said, where, srv.Name)
		}
		out.Changed = len(done.said) > 0
		if out.Changed {
			out.Changes = done.said
		}
		after := accessRow{Section: before.Section, Zone: before.SubItem, Users: users, Groups: groups}
		if out.Changed && !in.DryRun {
			change := technitium.AccessChange{Users: usersOf(users), Groups: groupsOfAccess(groups)}
			var now *technitium.Access
			if zone != "" {
				now, err = srv.Client.SetZonePermissions(ctx, zone, change)
			} else {
				now, err = srv.Client.SetSectionPermissions(ctx, section, change)
			}
			if err != nil {
				return nil, accessSetOut{}, fmt.Errorf("setting the permissions: %w", err)
			}
			after = accessRowOf(now)
		}
		out.After = &after

		return nil, out, nil
	})

	type ssoGetOut struct {
		Servers []ssoRow `json:"servers" jsonschema:"each server asked, with how it is set up for single sign-on"`
	}
	add(r, readTool, &mcp.Tool{
		Name:        "sso_get",
		Description: "How each server is set up for single sign-on with OpenID Connect: whether it is on, the provider and the client it signs in as, whether a first sign-in makes an account, and which groups at the provider map to which groups here. The client's secret is never read.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in serverArg) (*mcp.CallToolResult, ssoGetOut, error) {
		picked, err := r.servers.Pick(in.Server)
		if err != nil {
			return nil, ssoGetOut{}, err
		}
		answers := ask(ctx, picked, func(ctx context.Context, srv *servers.Server) (*technitium.SSO, error) {
			return srv.Client.SSO(ctx, false)
		})
		if _, err := failures(answers); err != nil {
			return nil, ssoGetOut{}, err
		}

		out := ssoGetOut{Servers: []ssoRow{}}
		for _, a := range answers {
			if a.Err != nil {
				out.Servers = append(out.Servers, ssoRow{Server: a.Server.Name, GroupMap: map[string]string{}, Error: a.Err.Error()})

				continue
			}
			out.Servers = append(out.Servers, ssoRowOf(a.Server.Name, a.Value))
		}

		return nil, out, nil
	})

	type ssoSetIn struct {
		writeServerArg

		Enabled                *bool              `json:"enabled,omitempty"                            jsonschema:"switch single sign-on on or off"`
		Authority              *string            `json:"authority,omitempty"                          jsonschema:"the provider's address; an empty one clears it"`
		ClientID               *string            `json:"client_id,omitempty"                          jsonschema:"the client this server signs in to the provider as; an empty one clears it"`
		ClientSecret           string             `json:"client_secret,omitempty"                      jsonschema:"that client's secret at the provider. It is never read back"`
		MetadataAddress        *string            `json:"metadata_address,omitempty"                   jsonschema:"where the provider describes itself, when that is not where its authority says; an empty one clears it"`
		AllowSignup            *bool              `json:"allow_signup,omitempty"                       jsonschema:"make an account here for whoever signs in through the provider for the first time"`
		AllowSignupOnlyForMaps *bool              `json:"allow_signup_only_for_mapped_users,omitempty" jsonschema:"and only for those in a group the group map names"`
		GroupMap               *map[string]string `json:"group_map,omitempty"                          jsonschema:"the whole map, in place of the one there is: each group at the provider with the group here its members are put in. An empty map clears it"`
		DryRun                 bool               `json:"dry_run,omitempty"                            jsonschema:"change nothing, and answer with what would be"`
	}
	type ssoSetOut struct {
		Server  string   `json:"server"`
		Changed bool     `json:"changed"`
		Changes []string `json:"changes"`
		After   *ssoRow  `json:"after,omitempty" jsonschema:"single sign-on as the server has it now, read back; absent from a dry run"`
		Note    string   `json:"note,omitempty"`
	}
	add(r, writeTool, &mcp.Tool{
		Name:        "sso_set",
		Description: "Change how a server is set up for single sign-on with OpenID Connect. Only what is given is changed. Switching it on needs the provider's authority, a client id and the client's secret, and has the server restart its console, which for a moment answers nothing. People who sign in through the provider get an account here on their first sign-in when signup is allowed, in the groups the map gives their groups at the provider.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in ssoSetIn) (*mcp.CallToolResult, ssoSetOut, error) {
		srv, err := r.servers.One(in.Server)
		if err != nil {
			return nil, ssoSetOut{}, err
		}
		before, err := srv.Client.SSO(ctx, true)
		if err != nil {
			return nil, ssoSetOut{}, fmt.Errorf("%s: %w", srv.Name, err)
		}

		change := technitium.SSOChange{ClientSecret: in.ClientSecret}
		done := &changes{dry: in.DryRun}
		if in.Enabled != nil && *in.Enabled != before.Enabled {
			change.Enabled = in.Enabled
			if *in.Enabled {
				done.did("switched single sign-on on, on %s", srv.Name)
			} else {
				done.did("switched single sign-on off, on %s", srv.Name)
			}
		}
		for _, text := range []struct {
			what string
			want *string
			now  string
			set  **string
		}{{"the provider's authority", in.Authority, before.Authority, &change.Authority}, {"the client id", in.ClientID, before.ClientID, &change.ClientID}, {"the provider's metadata address", in.MetadataAddress, before.MetadataAddress, &change.MetadataAddress}} {
			if text.want != nil && strings.TrimSpace(*text.want) != text.now {
				trimmed := strings.TrimSpace(*text.want)
				*text.set = &trimmed
				done.did("changed %s from %q to %q", text.what, text.now, trimmed)
			}
		}
		if in.ClientSecret != "" {
			done.did("set the client's secret")
		}
		if in.AllowSignup != nil && *in.AllowSignup != before.AllowSignup {
			change.AllowSignup = in.AllowSignup
			done.did("set whether a first sign-in makes an account to %v", *in.AllowSignup)
		}
		if in.AllowSignupOnlyForMaps != nil && *in.AllowSignupOnlyForMaps != before.AllowSignupOnlyForMappedUsers {
			change.AllowSignupOnlyForMappedUsers = in.AllowSignupOnlyForMaps
			done.did("set whether only those in a mapped group may sign up to %v", *in.AllowSignupOnlyForMaps)
		}
		if in.GroupMap != nil {
			was := ssoRowOf(srv.Name, before).GroupMap
			if !maps.Equal(was, *in.GroupMap) {
				mapping := []technitium.GroupMapping{}
				for remote, local := range *in.GroupMap {
					if !slices.ContainsFunc(before.LocalGroups, func(g string) bool { return strings.EqualFold(g, local) }) {
						return nil, ssoSetOut{}, fmt.Errorf("%s has no group named %s to map %s to: group_list names the groups", srv.Name, local, remote)
					}
					mapping = append(mapping, technitium.GroupMapping{RemoteGroup: remote, LocalGroup: local})
				}
				slices.SortFunc(mapping, func(a, b technitium.GroupMapping) int { return strings.Compare(a.RemoteGroup, b.RemoteGroup) })
				change.GroupMap = mapping
				done.did("set the group map to %d entries (it had %d)", len(mapping), len(was))
			}
		}
		enabling := change.Enabled != nil && *change.Enabled
		authority, clientID := before.Authority, before.ClientID
		if change.Authority != nil {
			authority = *change.Authority
		}
		if change.ClientID != nil {
			clientID = *change.ClientID
		}
		if enabling && (authority == "" || clientID == "") {
			return nil, ssoSetOut{}, errors.New("single sign-on is switched on with a provider to sign in through: give authority, client_id and client_secret")
		}

		out := ssoSetOut{Server: srv.Name, Changes: done.said, Changed: len(done.said) > 0}
		if out.Changes == nil {
			out.Changes = []string{}
		}
		if out.Changed && !in.DryRun {
			out.Note = "the server restarts its console when the change needs it, and for that moment answers nothing"
			if _, err := srv.Client.SetSSO(ctx, change); err != nil {
				return nil, ssoSetOut{}, fmt.Errorf("setting single sign-on: %w", err)
			}
		}
		if !in.DryRun {
			after, err := readSSOAgain(ctx, srv)
			if err != nil {
				return nil, ssoSetOut{}, fmt.Errorf("single sign-on was set and could not be read back: %w", err)
			}
			row := ssoRowOf(srv.Name, after)
			out.After = &row
		}

		return nil, out, nil
	})

	type accountOn struct {
		userDetail
	}
	type accountGetOut struct {
		Servers []accountOn `json:"servers" jsonschema:"each server asked, with the account the tool's token belongs to there"`
	}
	add(r, readTool, &mcp.Tool{
		Name:        "account_get",
		Description: "The account this tool itself works under on each server: whose token it holds, the groups that account is in - which is what the tool may do there - whether the account has a second factor, and every session and token it has, this one marked as current. It needs no administrator: any token may read its own account.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in serverArg) (*mcp.CallToolResult, accountGetOut, error) {
		picked, err := r.servers.Pick(in.Server)
		if err != nil {
			return nil, accountGetOut{}, err
		}
		answers := ask(ctx, picked, func(ctx context.Context, srv *servers.Server) (*technitium.Profile, error) {
			return srv.Client.Profile(ctx)
		})
		if _, err := failures(answers); err != nil {
			return nil, accountGetOut{}, err
		}

		out := accountGetOut{Servers: []accountOn{}}
		for _, a := range answers {
			if a.Err != nil {
				out.Servers = append(out.Servers, accountOn{userDetail{Server: a.Server.Name, Groups: []string{}, Sessions: []sessionRow{}, Error: a.Err.Error()}})

				continue
			}
			out.Servers = append(out.Servers, accountOn{userDetailOf(a.Server.Name, &technitium.User{Profile: *a.Value})})
		}

		return nil, out, nil
	})

	type accountEditIn struct {
		writeServerArg

		Username       string `json:"username"                          jsonschema:"the account to sign in as"`
		Password       string `json:"password"                          jsonschema:"its password, to sign in with. It is not kept or repeated"`
		TOTP           string `json:"totp,omitempty"                    jsonschema:"its one-time code, when the account has a second factor"`
		NewPassword    string `json:"new_password,omitempty"            jsonschema:"change the account's password to this"`
		DisplayName    string `json:"display_name,omitempty"            jsonschema:"change the account's name as people read it"`
		SessionTimeout int    `json:"session_timeout_seconds,omitempty" jsonschema:"change how long the account's sessions last with nothing using them"`
		TwoFactor      string `json:"two_factor,omitempty"              jsonschema:"begin: have the server make the secret an authenticator app is given, which the answer holds once; enable: switch the second factor on, with two_factor_code made by the app from that secret; disable: take it off"`
		TwoFactorCode  string `json:"two_factor_code,omitempty"         jsonschema:"for enable: the six digits the authenticator app shows"`
		CreateToken    string `json:"create_token,omitempty"            jsonschema:"make an API token for the account under this name; the answer holds it once"`
		SingleUseToken bool   `json:"single_use_token,omitempty"        jsonschema:"make a token for the account that works for one call and then is gone; the answer holds it once"`
		EndSession     string `json:"end_session,omitempty"             jsonschema:"end another of the account's sessions, or delete one of its tokens, by the id account_get gives it"`
	}
	type accountEditOut struct {
		Server          string      `json:"server"`
		Username        string      `json:"username"`
		Changes         []string    `json:"changes"`
		TwoFactorSecret string      `json:"two_factor_secret,omitempty" jsonschema:"for begin: the secret to type into an authenticator app. Whoever has it can make the account's codes"`
		TwoFactorURI    string      `json:"two_factor_uri,omitempty"    jsonschema:"for begin: the same secret as the address an authenticator app reads from a QR code"`
		Token           string      `json:"token,omitempty"             jsonschema:"for create_token or single_use_token: the token itself, shown this once"`
		After           *userDetail `json:"after,omitempty"             jsonschema:"the account as it now stands"`
		Note            string      `json:"note,omitempty"`
	}
	add(r, writeTool, &mcp.Tool{
		Name:        "account_edit",
		Description: "Change an account as the account itself, by signing in with its name and password: its own password, its name, how long its sessions last, a second factor put on or taken off, a token made for it, one of its sessions ended. These are the things a server lets only the account's owner do, and an API token is refused them - an administrator changes other people's accounts with user_set instead, which cannot put a second factor on. The tool signs in, makes the changes and signs out again. Putting a second factor on takes two calls: begin, which answers with the secret for an authenticator app, then enable with a code the app makes from it.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in accountEditIn) (*mcp.CallToolResult, accountEditOut, error) {
		name := strings.TrimSpace(in.Username)
		if name == "" || in.Password == "" {
			return nil, accountEditOut{}, errors.New("an account is changed as itself by signing in: give its username and password")
		}
		twoFactor := strings.ToLower(strings.TrimSpace(in.TwoFactor))
		if !slices.Contains([]string{"", "begin", "enable", "disable"}, twoFactor) {
			return nil, accountEditOut{}, fmt.Errorf("two_factor %q: it is begin, enable or disable", in.TwoFactor)
		}
		if twoFactor == "enable" && strings.TrimSpace(in.TwoFactorCode) == "" {
			return nil, accountEditOut{}, errors.New("a second factor is switched on with two_factor_code: the six digits the authenticator app shows for the secret begin gave")
		}
		if in.NewPassword == "" && in.DisplayName == "" && in.SessionTimeout == 0 && twoFactor == "" && in.CreateToken == "" && !in.SingleUseToken && in.EndSession == "" {
			return nil, accountEditOut{}, errors.New("nothing was given to change")
		}
		srv, err := r.servers.One(in.Server)
		if err != nil {
			return nil, accountEditOut{}, err
		}
		session, who, err := srv.Client.Login(ctx, name, in.Password, strings.TrimSpace(in.TOTP))
		if err != nil {
			return nil, accountEditOut{}, fmt.Errorf("signing in to %s as %s: %w", srv.Name, name, err)
		}
		// the session is ended whatever happens, and under a context that
		// outlives a call that was cut short
		defer func() { _ = session.Logout(context.WithoutCancel(ctx)) }()

		out := accountEditOut{Server: srv.Name, Username: who.Username, Changes: []string{}}
		said := func(format string, args ...any) { out.Changes = append(out.Changes, fmt.Sprintf(format, args...)) }
		if in.DisplayName != "" || in.SessionTimeout != 0 {
			if _, err := session.SetProfile(ctx, technitium.ProfileChange{DisplayName: in.DisplayName, SessionTimeoutSeconds: in.SessionTimeout}); err != nil {
				return nil, accountEditOut{}, fmt.Errorf("changing the profile: %w", err)
			}
			if in.DisplayName != "" {
				said("set the display name of %s to %q", who.Username, in.DisplayName)
			}
			if in.SessionTimeout != 0 {
				said("set the sessions of %s to last %d seconds", who.Username, in.SessionTimeout)
			}
		}
		switch twoFactor {
		case "begin":
			setup, setupErr := session.InitTwoFactor(ctx)
			if setupErr != nil {
				return nil, accountEditOut{}, fmt.Errorf("beginning a second factor: %w", setupErr)
			}
			out.TwoFactorSecret = setup.Secret
			out.TwoFactorURI = "otpauth://totp/" + who.Username + "?secret=" + setup.Secret + "&issuer=Technitium%20DNS%20Server"
			out.Note = "the second factor is not on yet: give the secret to an authenticator app, then call again with two_factor enable and the code the app shows"
			said("had the server make a second factor's secret for %s", who.Username)
		case "enable":
			if err := session.EnableTwoFactor(ctx, strings.TrimSpace(in.TwoFactorCode)); err != nil {
				return nil, accountEditOut{}, fmt.Errorf("switching the second factor on: %w", err)
			}
			said("switched the second factor of %s on: signing in takes a code from now on", who.Username)
		case "disable":
			if err := session.DisableTwoFactor(ctx); err != nil {
				return nil, accountEditOut{}, fmt.Errorf("taking the second factor off: %w", err)
			}
			said("took the second factor off %s", who.Username)
		default:
		}
		if in.EndSession != "" {
			if err := session.EndSession(ctx, strings.TrimSpace(in.EndSession)); err != nil {
				return nil, accountEditOut{}, fmt.Errorf("ending the session: %w", err)
			}
			said("ended the session %s of %s", strings.TrimSpace(in.EndSession), who.Username)
		}
		switch {
		case in.CreateToken != "" && in.SingleUseToken:
			return nil, accountEditOut{}, errors.New("create_token and single_use_token each answer with a token: ask for one of them at a time")
		case in.CreateToken != "":
			if out.Token, err = session.CreateToken(ctx, strings.TrimSpace(in.CreateToken)); err != nil {
				return nil, accountEditOut{}, fmt.Errorf("making the token: %w", err)
			}
			said("made the API token %q for %s", strings.TrimSpace(in.CreateToken), who.Username)
		case in.SingleUseToken:
			if out.Token, err = session.SingleUseToken(ctx); err != nil {
				return nil, accountEditOut{}, fmt.Errorf("making the token: %w", err)
			}
			said("made a token for %s that works for one call", who.Username)
		default:
		}
		// the password last: it is the one thing that changes what the rest
		// was signed in with
		if in.NewPassword != "" {
			if err := session.ChangePassword(ctx, in.Password, in.NewPassword, strings.TrimSpace(in.TOTP), 0); err != nil {
				return nil, accountEditOut{}, fmt.Errorf("changing the password: %w", err)
			}
			said("changed the password of %s", who.Username)
		}
		if profile, profileErr := session.Profile(ctx); profileErr == nil {
			detail := userDetailOf(srv.Name, &technitium.User{Profile: *profile})
			out.After = &detail
		}

		return nil, out, nil
	})
}

// readSSOAgain reads single sign-on once the server answers again: a change
// to it can have the server restart its console.
func readSSOAgain(ctx context.Context, srv *servers.Server) (*technitium.SSO, error) {
	if _, err := settledCluster(ctx, srv); err != nil {
		return nil, err
	}

	return srv.Client.SSO(ctx, false)
}
