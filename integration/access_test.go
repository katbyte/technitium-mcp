//go:build integration

package integration

import (
	"slices"
	"strings"
	"testing"

	"github.com/katbyte/technitium-mcp/lib/testenv"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
)

// reader makes an account for the length of a test and returns a client
// that works under a token of its own.
func reader(t *testing.T, c *technitium.Client, name string) *technitium.Client {
	t.Helper()

	ctx := t.Context()
	_ = c.DeleteUser(ctx, name)
	if _, err := c.CreateUser(ctx, technitium.NewUser{Username: name, Password: "a passw0rd for " + name}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.DeleteUser(noCancel(t), name) })
	token, err := c.CreateTokenAs(ctx, name, "it")
	if err != nil {
		t.Fatal(err)
	}
	as, err := technitium.New(c.BaseURL(), token)
	if err != nil {
		t.Fatal(err)
	}

	return as
}

func TestGroups(t *testing.T) {
	t.Parallel()

	c := first(t)
	ctx := t.Context()
	const name = "it-group"
	_ = c.DeleteGroup(ctx, name)
	_ = c.DeleteGroup(ctx, name+"-renamed")

	made, err := c.CreateGroup(ctx, name, "made by a test")
	if err != nil || made.Name != name || made.Description != "made by a test" {
		t.Fatalf("CreateGroup = %+v, %v", made, err)
	}
	t.Cleanup(func() { _ = c.DeleteGroup(noCancel(t), name); _ = c.DeleteGroup(noCancel(t), name+"-renamed") })
	if _, err := c.CreateGroup(ctx, name, ""); err == nil {
		t.Error("the group was made twice")
	}
	groups, err := c.Groups(ctx)
	if err != nil || !slices.ContainsFunc(groups, func(g technitium.Group) bool { return g.Name == name && g.Description == "made by a test" }) || !slices.ContainsFunc(groups, func(g technitium.Group) bool { return g.Name == "Administrators" }) {
		t.Errorf("Groups = %+v, %v", groups, err)
	}
	one, err := c.Group(ctx, name, true)
	if err != nil || one.Name != name || len(one.Members) != 0 || !slices.Contains(one.Users, "admin") {
		t.Errorf("Group = %+v, %v", one, err)
	}

	// renamed, its description cleared and a member put in, all at once; then emptied again
	changed, err := c.SetGroup(ctx, name, technitium.GroupChange{NewName: name + "-renamed", Description: new(""), Members: []string{"admin"}})
	if err != nil || changed.Name != name+"-renamed" || changed.Description != "" || !slices.Equal(changed.Members, []string{"admin"}) {
		t.Fatalf("SetGroup = %+v, %v", changed, err)
	}
	if admin, err := c.User(ctx, "admin", false); err != nil || !slices.Contains(admin.MemberOfGroups, name+"-renamed") {
		t.Errorf("the account put in the group is in %v, %v", admin.MemberOfGroups, err)
	}
	if changed, err = c.SetGroup(ctx, name+"-renamed", technitium.GroupChange{Members: []string{}}); err != nil || len(changed.Members) != 0 {
		t.Errorf("emptied = %+v, %v", changed, err)
	}
	if err := c.DeleteGroup(ctx, name+"-renamed"); err != nil {
		t.Errorf("DeleteGroup = %v", err)
	}
	if _, err := c.Group(ctx, name+"-renamed", false); err == nil {
		t.Error("a group that was deleted was read")
	}
}

// Who may do what in a section, and with one zone: read, set for one
// account, seen to hold when that account asks, and taken away again.
func TestPermissions(t *testing.T) {
	t.Parallel()

	c := first(t)
	ctx := t.Context()
	const name, z = "it-permitted", "permissions.it.test"
	as := reader(t, c, name)
	zone(t, c, z)

	all, err := c.Permissions(ctx)
	if err != nil || len(all) < 10 {
		t.Fatalf("Permissions = %d sections, %v", len(all), err)
	}
	for _, section := range all {
		if !slices.ContainsFunc(section.Groups, func(g technitium.GroupAccess) bool {
			return g.Name == "Administrators" && g.CanView && g.CanModify && g.CanDelete
		}) {
			t.Errorf("the administrators may not do everything in %s: %+v", section.Section, section.Groups)
		}
	}
	before, err := c.SectionPermissions(ctx, "Zones", true)
	if err != nil || before.Section != "Zones" || !slices.Contains(before.AllUsers, name) || !slices.Contains(before.AllGroups, "Administrators") || slices.ContainsFunc(before.Users, func(u technitium.UserAccess) bool { return u.Username == name }) {
		t.Fatalf("SectionPermissions = %+v, %v", before, err)
	}

	// the section: everyone may view it, which is listing the zones one may view oneself - none, for an account given nothing - and making one takes more
	sees := func() []string {
		t.Helper()
		zones, listErr := as.Zones(ctx, technitium.ZoneFilter{})
		if listErr != nil {
			t.Fatalf("the account could not list the zones: %v", listErr)
		}
		var names []string
		for _, held := range zones {
			if !held.Internal {
				names = append(names, held.Name)
			}
		}

		return names
	}
	if !slices.ContainsFunc(before.Groups, func(g technitium.GroupAccess) bool { return g.Name == "Everyone" && g.CanView && !g.CanModify }) {
		t.Errorf("everyone may not view the zones section and no more: %+v", before.Groups)
	}
	if got := sees(); len(got) != 0 {
		t.Errorf("an account given nothing sees the zones %v", got)
	}
	if _, err := as.CreateZone(ctx, technitium.NewZone{Name: "made.permissions.it.test", Type: technitium.ZonePrimary}); err == nil {
		_ = c.DeleteZone(ctx, "made.permissions.it.test")
		t.Error("an account that may only view the zones section made a zone")
	}
	after, err := c.SetSectionPermissions(ctx, "Zones", technitium.AccessChange{Users: append(slices.Clone(before.Users), technitium.UserAccess{Username: name, CanView: true, CanModify: true})})
	if err != nil || !slices.ContainsFunc(after.Users, func(u technitium.UserAccess) bool {
		return u.Username == name && u.CanView && u.CanModify && !u.CanDelete
	}) || !slices.Equal(after.Groups, before.Groups) {
		t.Fatalf("SetSectionPermissions = %+v, %v", after, err)
	}
	t.Cleanup(func() {
		_, _ = c.SetSectionPermissions(noCancel(t), "Zones", technitium.AccessChange{Users: before.Users})
		_ = c.DeleteZone(noCancel(t), "made.permissions.it.test")
	})
	if _, err := as.CreateZone(ctx, technitium.NewZone{Name: "made.permissions.it.test", Type: technitium.ZonePrimary}); err != nil {
		t.Errorf("an account that may modify the zones section could not make a zone: %v", err)
	}
	// the zone it made is its own to see; the one the administrator made is still not
	if got := sees(); !slices.Equal(got, []string{"made.permissions.it.test"}) {
		t.Errorf("the account sees the zones %v, want the one it made", got)
	}

	// one zone's own: the account may change this zone's records once it is given the zone, and may not delete it
	forZone, err := c.ZonePermissions(ctx, z, true)
	if err != nil || forZone.Section != "Zones" || forZone.SubItem != z || !slices.Contains(forZone.AllUsers, name) || !slices.ContainsFunc(forZone.Users, func(u technitium.UserAccess) bool { return u.Username == "admin" && u.CanDelete }) {
		t.Fatalf("ZonePermissions = %+v, %v", forZone, err)
	}
	if _, err := as.AddRecord(ctx, technitium.NewRecord{Zone: z, Name: "a." + z, Type: "A", Data: technitium.RData{"ipAddress": "10.7.7.7"}}); err == nil {
		t.Error("an account given nothing in the zone added a record to it")
	}
	set, err := c.SetZonePermissions(ctx, z, technitium.AccessChange{Users: append(slices.Clone(forZone.Users), technitium.UserAccess{Username: name, CanView: true, CanModify: true})})
	if err != nil || set.SubItem != z || !slices.ContainsFunc(set.Users, func(u technitium.UserAccess) bool {
		return u.Username == name && u.CanView && u.CanModify && !u.CanDelete
	}) || !slices.Equal(set.Groups, forZone.Groups) {
		t.Fatalf("SetZonePermissions = %+v, %v", set, err)
	}
	if _, err := as.AddRecord(ctx, technitium.NewRecord{Zone: z, Name: "a." + z, Type: "A", Data: technitium.RData{"ipAddress": "10.7.7.7"}}); err != nil {
		t.Errorf("an account that may modify the zone could not add a record to it: %v", err)
	}
	if got := sees(); !slices.Contains(got, z) {
		t.Errorf("the account sees the zones %v, want the one it was given among them", got)
	}
	if err := as.DeleteZone(ctx, z); err == nil {
		t.Error("an account that may not delete the zone deleted it")
	}

	// a list given with nobody in it is nobody's
	cleared, err := c.SetZonePermissions(ctx, z, technitium.AccessChange{Users: []technitium.UserAccess{}})
	if err != nil || len(cleared.Users) != 0 || !slices.Equal(cleared.Groups, forZone.Groups) {
		t.Errorf("cleared = %+v, %v", cleared, err)
	}
	if got := sees(); slices.Contains(got, z) {
		t.Errorf("the account still sees the zone it was taken off: %v", got)
	}
	if after, err = c.SetSectionPermissions(ctx, "Zones", technitium.AccessChange{Users: before.Users}); err != nil || slices.ContainsFunc(after.Users, func(u technitium.UserAccess) bool { return u.Username == name }) {
		t.Errorf("put back = %+v, %v", after, err)
	}
	if _, err := c.SectionPermissions(ctx, "NoSuchSection", false); err == nil {
		t.Error("a section that is not one was read")
	}
}

// Single sign-on is read, and what of it can be set without a provider to
// sign in through is set and read back.
//
// It does not run beside the other tests: a change to single sign-on can
// have the server restart its console.
//
//nolint:paralleltest // it changes single sign-on, which can restart the console every other test is asking
func TestSSO(t *testing.T) {
	ready(t)
	c := first(t)
	ctx := t.Context()

	before, err := c.SSO(ctx, true)
	if err != nil || before.Enabled || !slices.Contains(before.LocalGroups, "Administrators") {
		t.Fatalf("SSO = %+v, %v", before, err)
	}
	after, err := c.SetSSO(ctx, technitium.SSOChange{AllowSignupOnlyForMappedUsers: new(!before.AllowSignupOnlyForMappedUsers), GroupMap: []technitium.GroupMapping{{RemoteGroup: "it-remote", LocalGroup: "DNS Administrators"}}})
	if err != nil || after.AllowSignupOnlyForMappedUsers == before.AllowSignupOnlyForMappedUsers || len(after.GroupMap) != 1 || after.GroupMap[0].RemoteGroup != "it-remote" || after.GroupMap[0].LocalGroup != "DNS Administrators" {
		t.Errorf("SetSSO = %+v, %v", after, err)
	}
	back, err := c.SetSSO(ctx, technitium.SSOChange{AllowSignupOnlyForMappedUsers: new(before.AllowSignupOnlyForMappedUsers), GroupMap: []technitium.GroupMapping{}})
	if err != nil || back.AllowSignupOnlyForMappedUsers != before.AllowSignupOnlyForMappedUsers || len(back.GroupMap) != 0 {
		t.Errorf("put back = %+v, %v", back, err)
	}

	// the two calls a cluster's nodes make of each other: a server in no cluster has no use for them and says so, and one in a cluster takes them only under the cluster's own token
	want := "Cluster is not initialized"
	if world.Topology == testenv.Cluster {
		want = ""
	}
	_, err = c.CreateSSOUser(ctx, technitium.NewSSOUser{Username: "it-sso", Identifier: "sub-1"})
	if err == nil || !strings.Contains(err.Error(), want) {
		_ = c.DeleteUser(ctx, "it-sso")
		t.Errorf("CreateSSOUser under an administrator's token = %v", err)
	}
	_, err = c.SetSSOUser(ctx, "it-sso", technitium.SSOUserChange{DisplayName: "x"})
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("SetSSOUser under an administrator's token = %v", err)
	}
}
