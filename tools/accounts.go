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

// sessionRow is someone signed in to a server, or an API token made on it.
type sessionRow struct {
	ID        string `json:"id"                   jsonschema:"what the server knows the session by: the start of its token, which is not enough of it to use. session_delete takes it"`
	Username  string `json:"username"`
	Type      string `json:"type"                 jsonschema:"Standard for someone signed in at the console, which ends by itself, or ApiToken for a token, which does not"`
	TokenName string `json:"token_name,omitempty" jsonschema:"the name an API token was made under"`
	Current   bool   `json:"current,omitempty"    jsonschema:"this is the session the tool itself works under"`
	LastSeen  string `json:"last_seen,omitempty"  jsonschema:"when the session last made a call, UTC"`
	LastFrom  string `json:"last_from,omitempty"  jsonschema:"the address it last called from"`
	Agent     string `json:"agent,omitempty"      jsonschema:"what it last said it was: a browser, or a program's name"`
}

func sessionRows(sessions []technitium.OpenSession) []sessionRow {
	rows := make([]sessionRow, 0, len(sessions))
	for _, s := range sessions {
		rows = append(rows, sessionRow{ID: s.PartialToken, Username: s.Username, Type: s.Type, TokenName: s.TokenName, Current: s.IsCurrentSession, LastSeen: utc(s.LastSeen), LastFrom: s.LastSeenRemoteAddress, Agent: s.LastSeenUserAgent})
	}

	return rows
}

// userDetail is one account as a server holds it.
type userDetail struct {
	Server         string       `json:"server"`
	Username       string       `json:"username,omitempty"`
	DisplayName    string       `json:"display_name,omitempty"`
	Disabled       bool         `json:"disabled,omitempty"                jsonschema:"the account is switched off: nobody signs in as it and its tokens are refused"`
	SSO            bool         `json:"sso,omitempty"                     jsonschema:"the account signs in through single sign-on and has no password here"`
	TwoFactor      bool         `json:"two_factor,omitempty"              jsonschema:"signing in takes a one-time code beside the password"`
	SessionTimeout int          `json:"session_timeout_seconds,omitempty" jsonschema:"how long a session of the account's lasts with nothing using it"`
	Groups         []string     `json:"groups"                            jsonschema:"the groups the account is in, which is where what it may do comes from"`
	LastSignedIn   string       `json:"last_signed_in,omitempty"          jsonschema:"when the account last signed in, UTC"`
	LastFrom       string       `json:"last_from,omitempty"`
	Sessions       []sessionRow `json:"sessions"                          jsonschema:"who is signed in as the account, and its API tokens"`
	Missing        bool         `json:"missing,omitempty"                 jsonschema:"this server has no such account"`
	Error          string       `json:"error,omitempty"`
}

// signedIn is a time an account signed in as a tool gives it: the server
// writes the year 1 for never.
func signedIn(at string) string {
	if when, ok := technitium.ParseTime(at); !ok || when.Year() < 1970 {
		return ""
	}

	return utc(at)
}

func userDetailOf(server string, u *technitium.User) userDetail {
	out := userDetail{Server: server, Username: u.Username, DisplayName: u.DisplayName, Disabled: u.Disabled, SSO: u.IsSSOUser, TwoFactor: u.TOTPEnabled, SessionTimeout: u.SessionTimeoutSeconds, Groups: slices.Clone(u.MemberOfGroups), LastSignedIn: signedIn(u.RecentSessionLoggedOn), Sessions: sessionRows(u.Sessions)}
	if out.LastSignedIn != "" {
		out.LastFrom = u.RecentSessionRemoteAddress
	}
	if out.Groups == nil {
		out.Groups = []string{}
	}

	return out
}

// userOn reads an account on a server, nil when the server has none by the
// name.
func userOn(ctx context.Context, srv *servers.Server, name string) (*technitium.User, error) {
	users, err := srv.Client.Users(ctx)
	if err != nil {
		return nil, err
	}
	i := slices.IndexFunc(users, func(u technitium.User) bool { return strings.EqualFold(u.Username, name) })
	if i < 0 {
		return nil, nil //nolint:nilnil // an account that is not there is no error: it is what a tool then makes, or says is missing
	}

	// asked for by the name the server lists it under, whatever case it was given in
	return srv.Client.User(ctx, users[i].Username, false)
}

// ownAccount is the account the tool's own token on a server belongs to.
func ownAccount(ctx context.Context, srv *servers.Server) (string, error) {
	session, err := srv.Client.Session(ctx)
	if err != nil {
		return "", fmt.Errorf("%s: %w", srv.Name, err)
	}

	return session.Username, nil
}

// accessEntry is what one account or one group may do with something.
type accessEntry struct {
	Name   string `json:"name"             jsonschema:"the account's username, or the group's name"`
	View   bool   `json:"view,omitempty"   jsonschema:"may read it"`
	Modify bool   `json:"modify,omitempty" jsonschema:"may change it"`
	Delete bool   `json:"delete,omitempty" jsonschema:"may delete in it, which for most sections includes the changes that cannot be undone"`
}

// accessRow is who may do what in one section of a server, or with one zone.
type accessRow struct {
	Section string        `json:"section"`
	Zone    string        `json:"zone,omitempty"`
	Users   []accessEntry `json:"users"          jsonschema:"the accounts given something by name, beside what their groups give them"`
	Groups  []accessEntry `json:"groups"         jsonschema:"what the members of each group may do"`
}

func accessRowOf(a *technitium.Access) accessRow {
	row := accessRow{Section: a.Section, Zone: a.SubItem, Users: []accessEntry{}, Groups: []accessEntry{}}
	for _, u := range a.Users {
		row.Users = append(row.Users, accessEntry{Name: u.Username, View: u.CanView, Modify: u.CanModify, Delete: u.CanDelete})
	}
	for _, g := range a.Groups {
		row.Groups = append(row.Groups, accessEntry{Name: g.Name, View: g.CanView, Modify: g.CanModify, Delete: g.CanDelete})
	}

	return row
}

// may is an entry said in words: view, modify and delete.
func (e accessEntry) may() string {
	var can []string
	for name, allowed := range map[string]bool{"view": e.View, "modify": e.Modify, "delete": e.Delete} {
		if allowed {
			can = append(can, name)
		}
	}
	if len(can) == 0 {
		return "do nothing"
	}
	slices.SortFunc(can, func(a, b string) int {
		return strings.Index("view modify delete", a) - strings.Index("view modify delete", b)
	})

	return strings.Join(can, ", ")
}

// accessMerged is a list of permissions with some entries set and some
// taken away, and what was changed in words.
func accessMerged(kind string, current, set []accessEntry, remove []string) (out []accessEntry, said []string) {
	out = slices.Clone(current)
	for _, entry := range set {
		i := slices.IndexFunc(out, func(e accessEntry) bool { return strings.EqualFold(e.Name, entry.Name) })
		switch {
		case i < 0:
			out = append(out, entry)
			said = append(said, fmt.Sprintf("allowed the %s %s to %s", kind, entry.Name, entry.may()))
		case out[i].View != entry.View || out[i].Modify != entry.Modify || out[i].Delete != entry.Delete:
			said = append(said, fmt.Sprintf("changed what the %s %s may do from %s to %s", kind, out[i].Name, out[i].may(), entry.may()))
			out[i].View, out[i].Modify, out[i].Delete = entry.View, entry.Modify, entry.Delete
		default:
		}
	}
	for _, name := range remove {
		if i := slices.IndexFunc(out, func(e accessEntry) bool { return strings.EqualFold(e.Name, name) }); i >= 0 {
			said = append(said, fmt.Sprintf("removed what the %s %s was given by name, which was to %s", kind, out[i].Name, out[i].may()))
			out = slices.Delete(out, i, i+1)
		}
	}

	return out, said
}

func registerAccountTools(r *registry) {
	type userRow struct {
		Username     string   `json:"username"`
		DisplayName  string   `json:"display_name,omitempty"`
		Disabled     bool     `json:"disabled,omitempty"`
		SSO          bool     `json:"sso,omitempty"            jsonschema:"signs in through single sign-on"`
		LastSignedIn string   `json:"last_signed_in,omitempty" jsonschema:"when the account last signed in on the first server that has it, UTC; absent for never"`
		On           []string `json:"on"                       jsonschema:"the servers that have the account"`
		MissingOn    []string `json:"missing_on,omitempty"     jsonschema:"the servers asked that do not. The nodes of a cluster share their accounts; servers on their own each have their own"`
	}
	type userListOut struct {
		Users  []userRow       `json:"users"`
		Failed []serverFailure `json:"failed,omitempty"`
	}
	add(r, readTool, &mcp.Tool{
		Name:        "user_list",
		Description: "The accounts on each server, set side by side: who can sign in, which are switched off, when each last signed in, and which servers have each. user_get gives one account whole, with its groups, its sessions and its API tokens. Only an administrator's token may read them.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in serverArg) (*mcp.CallToolResult, userListOut, error) {
		picked, err := r.servers.Pick(in.Server)
		if err != nil {
			return nil, userListOut{}, err
		}
		answers := ask(ctx, picked, func(ctx context.Context, srv *servers.Server) ([]technitium.User, error) {
			return srv.Client.Users(ctx)
		})
		failed, err := failures(answers)
		if err != nil {
			return nil, userListOut{}, err
		}

		out := userListOut{Users: []userRow{}, Failed: failed}
		var asked []string
		for _, a := range answers {
			if a.Err != nil {
				continue
			}
			asked = append(asked, a.Server.Name)
			for _, u := range a.Value {
				i := slices.IndexFunc(out.Users, func(row userRow) bool { return strings.EqualFold(row.Username, u.Username) })
				if i < 0 {
					out.Users = append(out.Users, userRow{Username: u.Username, DisplayName: u.DisplayName, Disabled: u.Disabled, SSO: u.IsSSOUser, LastSignedIn: signedIn(u.RecentSessionLoggedOn)})
					i = len(out.Users) - 1
				}
				out.Users[i].On = append(out.Users[i].On, a.Server.Name)
			}
		}
		for i := range out.Users {
			for _, server := range asked {
				if !slices.Contains(out.Users[i].On, server) {
					out.Users[i].MissingOn = append(out.Users[i].MissingOn, server)
				}
			}
		}
		slices.SortFunc(out.Users, func(a, b userRow) int {
			return strings.Compare(strings.ToLower(a.Username), strings.ToLower(b.Username))
		})

		return nil, out, nil
	})

	type userGetIn struct {
		serverArg

		Username string `json:"username" jsonschema:"the account's username, as user_list gives it"`
	}
	type userGetOut struct {
		Username string       `json:"username"`
		Servers  []userDetail `json:"servers"  jsonschema:"the account on each server asked"`
	}
	add(r, readTool, &mcp.Tool{
		Name:        "user_get",
		Description: "One account whole, on each server: whether it is switched off, whether signing in takes a second factor, the groups it is in - which is where what it may do comes from (access_get) - how long its sessions last, who is signed in as it, and its API tokens by name with when each was last used and from where. A token no one remembers making, or one last seen from an address that is not yours, is what session_delete is for.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in userGetIn) (*mcp.CallToolResult, userGetOut, error) {
		name := strings.TrimSpace(in.Username)
		if name == "" {
			return nil, userGetOut{}, errors.New("which account: give its username, as user_list gives it")
		}
		picked, err := r.servers.Pick(in.Server)
		if err != nil {
			return nil, userGetOut{}, err
		}
		answers := ask(ctx, picked, func(ctx context.Context, srv *servers.Server) (*technitium.User, error) {
			return userOn(ctx, srv, name)
		})
		if _, err := failures(answers); err != nil {
			return nil, userGetOut{}, err
		}

		out := userGetOut{Username: name, Servers: []userDetail{}}
		found := false
		for _, a := range answers {
			switch {
			case a.Err != nil:
				out.Servers = append(out.Servers, userDetail{Server: a.Server.Name, Groups: []string{}, Sessions: []sessionRow{}, Error: a.Err.Error()})
			case a.Value == nil:
				out.Servers = append(out.Servers, userDetail{Server: a.Server.Name, Groups: []string{}, Sessions: []sessionRow{}, Missing: true})
			default:
				found = true
				out.Servers = append(out.Servers, userDetailOf(a.Server.Name, a.Value))
			}
		}
		if !found {
			return nil, userGetOut{}, fmt.Errorf("no server asked has an account named %s: user_list names the accounts", name)
		}

		return nil, out, nil
	})

	type userSetIn struct {
		writeServerArg

		Username         string    `json:"username"                          jsonschema:"the account's username: one that is there is changed, and one that is not is made"`
		NewPassword      string    `json:"new_password,omitempty"            jsonschema:"the password a new account is made with, or one to reset an account's to. It is never repeated back"`
		DisplayName      string    `json:"display_name,omitempty"            jsonschema:"the account's name as people read it"`
		Groups           *[]string `json:"groups,omitempty"                  jsonschema:"the groups the account is in from now on, in place of the ones it was in: group_list names them. An empty list takes it out of every group, leaving it what Everyone may do"`
		Disabled         *bool     `json:"disabled,omitempty"                jsonschema:"true switches the account off, which signs out whoever is signed in as it and has its tokens refused; false switches it back on"`
		SessionTimeout   int       `json:"session_timeout_seconds,omitempty" jsonschema:"how long a session of the account's lasts with nothing using it"`
		NewUsername      string    `json:"new_username,omitempty"            jsonschema:"rename the account"`
		DisableTwoFactor bool      `json:"disable_two_factor,omitempty"      jsonschema:"take the account's second factor off, for someone who has lost theirs. One cannot be put on for somebody else: account_edit does that as the account itself"`
		DryRun           bool      `json:"dry_run,omitempty"                 jsonschema:"change nothing, and answer with what would be"`
	}
	type userSetOut struct {
		Server  string      `json:"server"`
		Changed bool        `json:"changed"           jsonschema:"something was changed; with a dry run, something would be"`
		Created bool        `json:"created,omitempty"`
		Changes []string    `json:"changes"           jsonschema:"each change made; with a dry run, each that would be"`
		After   *userDetail `json:"after,omitempty"   jsonschema:"the account as the server holds it now, read back; absent from a dry run"`
		Note    string      `json:"note,omitempty"`
	}
	add(r, writeTool, &mcp.Tool{
		Name:        "user_set",
		Description: "Make an account on a server, or change one that is there: its password, its name, the groups it is in, whether it is switched off, how long its sessions last. A new account needs a password, and is in no group but Everyone until groups are given: what it may do comes from its groups (group_list, access_get). Only what is given is changed. The account this tool works under cannot be switched off or taken out of the administrators here, which would lock the tool out. On a cluster, accounts are changed on the primary and reach every node.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in userSetIn) (*mcp.CallToolResult, userSetOut, error) {
		name := strings.TrimSpace(in.Username)
		if name == "" {
			return nil, userSetOut{}, errors.New("which account: give its username")
		}
		srv, err := r.servers.One(in.Server)
		if err != nil {
			return nil, userSetOut{}, err
		}
		before, err := userOn(ctx, srv, name)
		if err != nil {
			return nil, userSetOut{}, fmt.Errorf("%s: %w", srv.Name, err)
		}
		groups := given(in.Groups)
		own, err := ownAccount(ctx, srv)
		if err != nil {
			return nil, userSetOut{}, err
		}
		if strings.EqualFold(own, name) && ((in.Disabled != nil && *in.Disabled) || (groups != nil && !slices.Contains(groups, "Administrators"))) {
			return nil, userSetOut{}, fmt.Errorf("%s is the account this tool works under on %s: switched off, or out of the Administrators group, it could put nothing right again", own, srv.Name)
		}

		out := userSetOut{Server: srv.Name}
		done := &changes{dry: in.DryRun}
		if before != nil {
			name = before.Username
		}
		if before == nil {
			if in.NewPassword == "" {
				return nil, userSetOut{}, fmt.Errorf("%s has no account named %s, and one is made with a password: give new_password", srv.Name, name)
			}
			out.Created = true
			if done.did("made the account %s on %s", name, srv.Name) {
				if _, err := srv.Client.CreateUser(ctx, technitium.NewUser{Username: name, Password: in.NewPassword, DisplayName: in.DisplayName}); err != nil {
					return nil, userSetOut{}, fmt.Errorf("making the account: %w", err)
				}
			}
			before = &technitium.User{Username: name, DisplayName: in.DisplayName, MemberOfGroups: []string{}}
		}

		change := technitium.UserChange{}
		if !out.Created && in.NewPassword != "" {
			change.NewPassword = in.NewPassword
			done.did("reset the password of %s", name)
		}
		if in.DisplayName != "" && in.DisplayName != before.DisplayName && !out.Created {
			change.DisplayName = in.DisplayName
			done.did("changed the display name of %s from %q to %q", name, before.DisplayName, in.DisplayName)
		}
		if groups != nil {
			was := slices.Clone(before.MemberOfGroups)
			slices.Sort(was)
			want := slices.Clone(groups)
			slices.Sort(want)
			if !slices.Equal(was, want) {
				change.MemberOfGroups = groups
				done.did("set the groups of %s to %s (it was in %s)", name, orNone(groups), orNone(before.MemberOfGroups))
			}
		}
		if in.Disabled != nil && *in.Disabled != before.Disabled {
			change.Disabled = in.Disabled
			if *in.Disabled {
				done.did("switched the account %s off", name)
			} else {
				done.did("switched the account %s back on", name)
			}
		}
		if in.SessionTimeout != 0 && in.SessionTimeout != before.SessionTimeoutSeconds {
			change.SessionTimeoutSeconds = in.SessionTimeout
			done.did("set the sessions of %s to last %d seconds", name, in.SessionTimeout)
		}
		if in.DisableTwoFactor && (before.TOTPEnabled || out.Created) {
			change.DisableTwoFactor = true
			done.did("removed the second factor of %s", name)
		}
		renamed := strings.TrimSpace(in.NewUsername)
		if renamed != "" && !strings.EqualFold(renamed, name) {
			change.NewUsername = renamed
			done.did("renamed the account %s to %s", name, renamed)
		}
		changing := change.NewPassword != "" || change.DisplayName != "" || change.MemberOfGroups != nil || change.Disabled != nil || change.SessionTimeoutSeconds != 0 || change.DisableTwoFactor || change.NewUsername != ""
		if changing && !in.DryRun {
			if _, err := srv.Client.SetUser(ctx, name, change); err != nil {
				return nil, userSetOut{}, fmt.Errorf("changing the account: %w", err)
			}
		}
		out.Changes, out.Changed = done.said, len(done.said) > 0
		if out.Changes == nil {
			out.Changes = []string{}
		}
		if !in.DryRun {
			if change.NewUsername != "" {
				name = change.NewUsername
			}
			after, err := userOn(ctx, srv, name)
			if err != nil {
				return nil, userSetOut{}, fmt.Errorf("the account was changed and could not be read back: %w", err)
			}
			if after == nil {
				return nil, userSetOut{}, fmt.Errorf("the server said ok and %s has no account named %s", srv.Name, name)
			}
			detail := userDetailOf(srv.Name, after)
			out.After = &detail
		}

		return nil, out, nil
	})

	type userDeleteIn struct {
		writeServerArg

		Username string `json:"username"          jsonschema:"the account's username, as user_list gives it"`
		DryRun   bool   `json:"dry_run,omitempty" jsonschema:"delete nothing, and answer with what would be"`
	}
	type userDeleteOut struct {
		Server   string   `json:"server"`
		Changed  bool     `json:"changed"`
		Changes  []string `json:"changes"`
		Sessions int      `json:"sessions"       jsonschema:"how many sessions and API tokens the account had, which went with it"`
		Note     string   `json:"note,omitempty"`
	}
	add(r, deleteTool, &mcp.Tool{
		Name:        "user_delete",
		Description: "Delete an account from a server, and with it every session and API token it had: whatever was using one of its tokens stops working at once. There is no undo. Switching an account off instead (user_set with disabled) keeps it and its tokens for later. The account this tool works under is refused.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in userDeleteIn) (*mcp.CallToolResult, userDeleteOut, error) {
		name := strings.TrimSpace(in.Username)
		if name == "" {
			return nil, userDeleteOut{}, errors.New("which account: give its username, as user_list gives it")
		}
		srv, err := r.servers.One(in.Server)
		if err != nil {
			return nil, userDeleteOut{}, err
		}
		before, err := userOn(ctx, srv, name)
		if err != nil {
			return nil, userDeleteOut{}, fmt.Errorf("%s: %w", srv.Name, err)
		}
		out := userDeleteOut{Server: srv.Name, Changes: []string{}}
		if before == nil {
			out.Note = "the server has no such account: there is nothing to delete"

			return nil, out, nil
		}
		own, err := ownAccount(ctx, srv)
		if err != nil {
			return nil, userDeleteOut{}, err
		}
		if strings.EqualFold(own, before.Username) {
			return nil, userDeleteOut{}, fmt.Errorf("%s is the account this tool works under on %s: deleted, the tool's own token would go with it", own, srv.Name)
		}

		out.Changed, out.Sessions = true, len(before.Sessions)
		done := &changes{dry: in.DryRun}
		if done.did("deleted the account %s on %s with its %d sessions and tokens", before.Username, srv.Name, len(before.Sessions)) {
			if err := srv.Client.DeleteUser(ctx, before.Username); err != nil {
				return nil, userDeleteOut{}, fmt.Errorf("deleting the account: %w", err)
			}
		}
		out.Changes = done.said

		return nil, out, nil
	})

	type groupRow struct {
		Name        string   `json:"name"`
		Description string   `json:"description,omitempty"`
		Members     []string `json:"members"               jsonschema:"the accounts in the group"`
	}
	type groupsOn struct {
		Server string     `json:"server"`
		Groups []groupRow `json:"groups"`
		Error  string     `json:"error,omitempty"`
	}
	type groupListOut struct {
		Servers []groupsOn `json:"servers" jsonschema:"each server asked, with its groups and who is in each"`
	}
	groupsOf := func(ctx context.Context, srv *servers.Server) ([]groupRow, error) {
		groups, err := srv.Client.Groups(ctx)
		if err != nil {
			return nil, err
		}
		rows := []groupRow{}
		for _, g := range groups {
			detail, err := srv.Client.Group(ctx, g.Name, false)
			if err != nil {
				return nil, err
			}
			members := slices.Clone(detail.Members)
			if members == nil {
				members = []string{}
			}
			rows = append(rows, groupRow{Name: detail.Name, Description: detail.Description, Members: members})
		}

		return rows, nil
	}
	add(r, readTool, &mcp.Tool{
		Name:        "group_list",
		Description: "The groups on each server and who is in each. What an account may do comes from its groups: every section of a server - Zones, Settings, Logs and the rest - says what each group may view, modify and delete in it (access_get). A server comes with Administrators, who may do everything; DNS Administrators and DHCP Administrators, for those two parts; and Everyone, which every account is in.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in serverArg) (*mcp.CallToolResult, groupListOut, error) {
		picked, err := r.servers.Pick(in.Server)
		if err != nil {
			return nil, groupListOut{}, err
		}
		answers := ask(ctx, picked, groupsOf)
		if _, err := failures(answers); err != nil {
			return nil, groupListOut{}, err
		}

		out := groupListOut{Servers: []groupsOn{}}
		for _, a := range answers {
			row := groupsOn{Server: a.Server.Name, Groups: a.Value}
			if a.Err != nil {
				row.Groups, row.Error = []groupRow{}, a.Err.Error()
			}
			out.Servers = append(out.Servers, row)
		}

		return nil, out, nil
	})

	type groupSetIn struct {
		writeServerArg

		Group       string    `json:"group"                 jsonschema:"the group's name: one that is there is changed, and one that is not is made"`
		Description *string   `json:"description,omitempty" jsonschema:"what the group is for; an empty one clears it"`
		Members     *[]string `json:"members,omitempty"     jsonschema:"the accounts in the group from now on, in place of the ones that were: an empty list empties it"`
		NewName     string    `json:"new_name,omitempty"    jsonschema:"rename the group"`
		DryRun      bool      `json:"dry_run,omitempty"     jsonschema:"change nothing, and answer with what would be"`
	}
	type groupSetOut struct {
		Server  string    `json:"server"`
		Changed bool      `json:"changed"`
		Created bool      `json:"created,omitempty"`
		Changes []string  `json:"changes"`
		After   *groupRow `json:"after,omitempty"   jsonschema:"the group as the server holds it now, read back; absent from a dry run"`
	}
	add(r, writeTool, &mcp.Tool{
		Name:        "group_set",
		Description: "Make a group on a server, or change one that is there: what it is for, who is in it, its name. A new group may do nothing until a section or a zone gives it something (access_set). Only what is given is changed, and members replaces the whole membership. The account this tool works under cannot be taken out of Administrators here.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in groupSetIn) (*mcp.CallToolResult, groupSetOut, error) {
		name := strings.TrimSpace(in.Group)
		if name == "" {
			return nil, groupSetOut{}, errors.New("which group: give its name")
		}
		srv, err := r.servers.One(in.Server)
		if err != nil {
			return nil, groupSetOut{}, err
		}
		groups, err := groupsOf(ctx, srv)
		if err != nil {
			return nil, groupSetOut{}, fmt.Errorf("%s: %w", srv.Name, err)
		}
		members := given(in.Members)
		if members != nil && strings.EqualFold(name, "Administrators") {
			own, err := ownAccount(ctx, srv)
			if err != nil {
				return nil, groupSetOut{}, err
			}
			if !slices.ContainsFunc(members, func(m string) bool { return strings.EqualFold(m, own) }) {
				return nil, groupSetOut{}, fmt.Errorf("%s is the account this tool works under on %s: out of the Administrators group, it could put nothing right again", own, srv.Name)
			}
		}

		out := groupSetOut{Server: srv.Name}
		done := &changes{dry: in.DryRun}
		i := slices.IndexFunc(groups, func(g groupRow) bool { return strings.EqualFold(g.Name, name) })
		before := groupRow{Name: name, Members: []string{}}
		if i >= 0 {
			before = groups[i]
		} else {
			out.Created = true
			description := deref(in.Description)
			if done.did("made the group %s on %s", name, srv.Name) {
				if _, err := srv.Client.CreateGroup(ctx, name, description); err != nil {
					return nil, groupSetOut{}, fmt.Errorf("making the group: %w", err)
				}
			}
			before.Description = description
		}

		change := technitium.GroupChange{}
		if in.Description != nil && *in.Description != before.Description {
			change.Description = in.Description
			done.did("changed what the group %s is for from %q to %q", before.Name, before.Description, *in.Description)
		}
		if members != nil {
			was, want := slices.Clone(before.Members), slices.Clone(members)
			slices.Sort(was)
			slices.Sort(want)
			if !slices.Equal(was, want) {
				change.Members = members
				done.did("set the members of %s to %s (they were %s)", before.Name, orNone(members), orNone(before.Members))
			}
		}
		renamed := strings.TrimSpace(in.NewName)
		if renamed != "" && renamed != before.Name {
			change.NewName = renamed
			done.did("renamed the group %s to %s", before.Name, renamed)
		}
		if (change.Description != nil || change.Members != nil || change.NewName != "") && !in.DryRun {
			if _, err := srv.Client.SetGroup(ctx, before.Name, change); err != nil {
				return nil, groupSetOut{}, fmt.Errorf("changing the group: %w", err)
			}
		}
		out.Changes, out.Changed = done.said, len(done.said) > 0
		if out.Changes == nil {
			out.Changes = []string{}
		}
		if !in.DryRun {
			final := before.Name
			if change.NewName != "" {
				final = change.NewName
			}
			detail, err := srv.Client.Group(ctx, final, false)
			if err != nil {
				return nil, groupSetOut{}, fmt.Errorf("the group was changed and could not be read back: %w", err)
			}
			after := groupRow{Name: detail.Name, Description: detail.Description, Members: slices.Clone(detail.Members)}
			if after.Members == nil {
				after.Members = []string{}
			}
			out.After = &after
		}

		return nil, out, nil
	})

	type groupDeleteIn struct {
		writeServerArg

		Group  string `json:"group"             jsonschema:"the group's name, as group_list gives it"`
		DryRun bool   `json:"dry_run,omitempty" jsonschema:"delete nothing, and answer with what would be"`
	}
	type groupDeleteOut struct {
		Server  string   `json:"server"`
		Changed bool     `json:"changed"`
		Changes []string `json:"changes"`
		Members []string `json:"members"        jsonschema:"the accounts that were in the group, which lose what it gave them"`
		Note    string   `json:"note,omitempty"`
	}
	add(r, deleteTool, &mcp.Tool{
		Name:        "group_delete",
		Description: "Delete a group from a server. Its members keep their accounts and lose whatever the group gave them: every section and zone that named the group no longer does. The groups a server comes with are its own to keep, and it refuses to delete them.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in groupDeleteIn) (*mcp.CallToolResult, groupDeleteOut, error) {
		name := strings.TrimSpace(in.Group)
		if name == "" {
			return nil, groupDeleteOut{}, errors.New("which group: give its name, as group_list gives it")
		}
		srv, err := r.servers.One(in.Server)
		if err != nil {
			return nil, groupDeleteOut{}, err
		}
		groups, err := groupsOf(ctx, srv)
		if err != nil {
			return nil, groupDeleteOut{}, fmt.Errorf("%s: %w", srv.Name, err)
		}
		out := groupDeleteOut{Server: srv.Name, Changes: []string{}, Members: []string{}}
		i := slices.IndexFunc(groups, func(g groupRow) bool { return strings.EqualFold(g.Name, name) })
		if i < 0 {
			out.Note = "the server has no such group: there is nothing to delete"

			return nil, out, nil
		}

		out.Changed, out.Members = true, groups[i].Members
		done := &changes{dry: in.DryRun}
		if done.did("deleted the group %s on %s, which had %d members", groups[i].Name, srv.Name, len(groups[i].Members)) {
			if err := srv.Client.DeleteGroup(ctx, groups[i].Name); err != nil {
				return nil, groupDeleteOut{}, fmt.Errorf("deleting the group: %w", err)
			}
		}
		out.Changes = done.said

		return nil, out, nil
	})

	type sessionsOn struct {
		Server   string       `json:"server"`
		Sessions []sessionRow `json:"sessions"`
		Error    string       `json:"error,omitempty"`
	}
	type sessionListOut struct {
		Servers []sessionsOn `json:"servers" jsonschema:"each server asked, with who is signed in to it and the API tokens made on it"`
	}
	add(r, readTool, &mcp.Tool{
		Name:        "session_list",
		Description: "Who is signed in to each server and every API token made on it: whose it is, the name a token was made under, when it was last used, from which address and by what. A token does not expire, so this is the list of everything that can act on a server without a password: a token nobody recognises, or one last used from somewhere unexpected, is deleted with session_delete. Nothing of a token but the start of it is ever given.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in serverArg) (*mcp.CallToolResult, sessionListOut, error) {
		picked, err := r.servers.Pick(in.Server)
		if err != nil {
			return nil, sessionListOut{}, err
		}
		answers := ask(ctx, picked, func(ctx context.Context, srv *servers.Server) ([]technitium.OpenSession, error) {
			return srv.Client.Sessions(ctx)
		})
		if _, err := failures(answers); err != nil {
			return nil, sessionListOut{}, err
		}

		out := sessionListOut{Servers: []sessionsOn{}}
		for _, a := range answers {
			row := sessionsOn{Server: a.Server.Name, Sessions: sessionRows(a.Value)}
			if a.Err != nil {
				row.Error = a.Err.Error()
			}
			out.Servers = append(out.Servers, row)
		}

		return nil, out, nil
	})

	type sessionDeleteIn struct {
		writeServerArg

		ID     string `json:"id"                jsonschema:"the session or token, by the id session_list gives it"`
		DryRun bool   `json:"dry_run,omitempty" jsonschema:"end nothing, and answer with what would be"`
	}
	type sessionDeleteOut struct {
		Server  string      `json:"server"`
		Changed bool        `json:"changed"`
		Changes []string    `json:"changes"`
		Ended   *sessionRow `json:"ended,omitempty" jsonschema:"the session or token as it was"`
		Note    string      `json:"note,omitempty"`
	}
	add(r, deleteTool, &mcp.Tool{
		Name:        "session_delete",
		Description: "End one session on a server, or delete one API token, by its id: whoever was signed in is signed out, and whatever was using the token is refused from its next call. A deleted token cannot be brought back, only replaced with a new one (token_create). The token this tool itself works under is refused.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in sessionDeleteIn) (*mcp.CallToolResult, sessionDeleteOut, error) {
		id := strings.TrimSpace(in.ID)
		if id == "" {
			return nil, sessionDeleteOut{}, errors.New("which session: give its id, as session_list gives it")
		}
		srv, err := r.servers.One(in.Server)
		if err != nil {
			return nil, sessionDeleteOut{}, err
		}
		sessions, err := srv.Client.Sessions(ctx)
		if err != nil {
			return nil, sessionDeleteOut{}, fmt.Errorf("%s: %w", srv.Name, err)
		}
		out := sessionDeleteOut{Server: srv.Name, Changes: []string{}}
		i := slices.IndexFunc(sessions, func(s technitium.OpenSession) bool { return s.PartialToken == id })
		if i < 0 {
			out.Note = "the server has no session or token with that id: there is nothing to end"

			return nil, out, nil
		}
		if sessions[i].IsCurrentSession {
			return nil, sessionDeleteOut{}, fmt.Errorf("%s is the token this tool works under on %s: deleted, the tool could do nothing more there", id, srv.Name)
		}

		ended := sessionRows(sessions[i : i+1])[0]
		out.Changed, out.Ended = true, &ended
		what := "ended the session of " + ended.Username
		if ended.Type == technitium.SessionAPIToken {
			what = fmt.Sprintf("deleted the API token %q of %s", ended.TokenName, ended.Username)
		}
		done := &changes{dry: in.DryRun}
		if done.did("%s on %s", what, srv.Name) {
			if err := srv.Client.DeleteSession(ctx, id); err != nil {
				return nil, sessionDeleteOut{}, fmt.Errorf("ending the session: %w", err)
			}
		}
		out.Changes = done.said

		return nil, out, nil
	})

	type tokenCreateIn struct {
		writeServerArg

		Username  string `json:"username"   jsonschema:"the account the token acts as, as user_list gives it: the token may do what that account may, no more"`
		TokenName string `json:"token_name" jsonschema:"a name that says what the token is for, which is how it is told apart in session_list later"`
	}
	type tokenCreateOut struct {
		Server    string `json:"server"`
		Username  string `json:"username"`
		TokenName string `json:"token_name"`
		Token     string `json:"token"      jsonschema:"the token itself. The server never shows it again: it is given to whatever will use it, and kept nowhere else"`
		Note      string `json:"note"`
	}
	add(r, writeTool, &mcp.Tool{
		Name:        "token_create",
		Description: "Make an API token for an account on a server. The token acts as that account - it may do what the account may, so make an account with only what the job needs (user_set, access_set) rather than a token for an administrator - and does not expire: it works until it is deleted (session_delete) or its account is. The answer holds the token, once: it cannot be read again afterwards, so hand it straight to whoever asked for it.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in tokenCreateIn) (*mcp.CallToolResult, tokenCreateOut, error) {
		name, tokenName := strings.TrimSpace(in.Username), strings.TrimSpace(in.TokenName)
		if name == "" || tokenName == "" {
			return nil, tokenCreateOut{}, errors.New("a token is made for an account, under a name that says what it is for: give username and token_name")
		}
		srv, err := r.servers.One(in.Server)
		if err != nil {
			return nil, tokenCreateOut{}, err
		}
		account, err := userOn(ctx, srv, name)
		if err != nil {
			return nil, tokenCreateOut{}, fmt.Errorf("%s: %w", srv.Name, err)
		}
		if account == nil {
			return nil, tokenCreateOut{}, fmt.Errorf("%s has no account named %s: user_list names the accounts, and user_set makes one", srv.Name, name)
		}
		named := func(s technitium.OpenSession) bool {
			return s.Type == technitium.SessionAPIToken && s.TokenName == tokenName
		}
		if slices.ContainsFunc(account.Sessions, named) {
			return nil, tokenCreateOut{}, fmt.Errorf("%s already has a token named %q on %s: a name tells one token from another, so give this one its own", account.Username, tokenName, srv.Name)
		}
		token, err := srv.Client.CreateTokenAs(ctx, account.Username, tokenName)
		if err != nil {
			return nil, tokenCreateOut{}, fmt.Errorf("making the token: %w", err)
		}

		return nil, tokenCreateOut{Server: srv.Name, Username: account.Username, TokenName: tokenName, Token: token, Note: "this is the only time the token is shown: give it to whoever asked for it and keep it nowhere else. session_delete deletes it"}, nil
	})
}
