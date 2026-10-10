package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/katbyte/technitium-mcp/lib/servers"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// appRow is an app installed on a server.
type appRow struct {
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	Does     []string `json:"does"                   jsonschema:"what the app adds to the server, by the class of each part: app records name a part by it"`
	LogsHere bool     `json:"logs_queries,omitempty" jsonschema:"the app keeps the searchable log of queries"`
	Latest   string   `json:"latest,omitempty"       jsonschema:"the version the store has, when it is another"`
}

func appRowOf(app *technitium.App) appRow {
	row := appRow{Name: app.Name, Version: app.Version, Does: []string{}, LogsHere: app.LogsQueries()}
	for _, part := range app.Parts {
		row.Does = append(row.Does, part.ClassPath)
	}

	return row
}

// installedOn is an app as a server has it installed, nil when it has not.
func installedOn(ctx context.Context, srv *servers.Server, name string) (*technitium.App, error) {
	apps, err := srv.Client.Apps(ctx)
	if err != nil {
		return nil, err
	}
	if i := slices.IndexFunc(apps, func(a technitium.App) bool { return strings.EqualFold(a.Name, name) }); i >= 0 {
		return &apps[i], nil
	}

	return nil, nil //nolint:nilnil // an app that is not installed is no error: it is what a tool then installs, or says is missing
}

// storeOf is what the store offers as a server sees it, or why the server
// could not ask.
func storeOf(ctx context.Context, srv *servers.Server) (store []technitium.StoreApp, unreached string) {
	store, err := srv.Client.StoreApps(ctx)
	if err != nil {
		return nil, "the store could not be asked: " + err.Error()
	}

	return store, ""
}

func registerAppTools(r *registry) {
	type storeRow struct {
		Name        string `json:"name"`
		Version     string `json:"version"`
		Description string `json:"description,omitempty"`
		Size        string `json:"size,omitempty"`
	}
	type appsOn struct {
		Server    string     `json:"server"`
		Installed []appRow   `json:"installed"`
		Store     []storeRow `json:"store,omitempty"      jsonschema:"the apps the store offers that this server has not installed, when asked for"`
		StoreNote string     `json:"store_note,omitempty"`
		Error     string     `json:"error,omitempty"`
	}
	type appListIn struct {
		serverArg

		Store bool `json:"store,omitempty" jsonschema:"also ask the server's maker's store what it offers: which installed apps have a newer version there, and what else can be installed. The server asks over the internet"`
	}
	type appListOut struct {
		Servers []appsOn `json:"servers"`
	}
	add(r, readTool, &mcp.Tool{
		Name:        "app_list",
		Description: "The DNS apps installed on each server: plug-ins that add what the server does not do by itself - the log of queries, split horizon answers, failover records, blocking by client, and more. Each is given with its version and its parts, which is what an APP record in a zone names. With store the server asks its maker's store, and the answer says which installed apps have a newer version and what else is there to install (app_install). app_config_get reads an app's configuration.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in appListIn) (*mcp.CallToolResult, appListOut, error) {
		picked, err := r.servers.Pick(in.Server)
		if err != nil {
			return nil, appListOut{}, err
		}
		answers := ask(ctx, picked, func(ctx context.Context, srv *servers.Server) (appsOn, error) {
			row := appsOn{Server: srv.Name, Installed: []appRow{}}
			apps, err := srv.Client.Apps(ctx)
			if err != nil {
				return row, err
			}
			for i := range apps {
				row.Installed = append(row.Installed, appRowOf(&apps[i]))
			}
			if !in.Store {
				return row, nil
			}
			// the store is the server's maker's site, which a server may not reach: what is installed is still the answer
			store, unreached := storeOf(ctx, srv)
			if unreached != "" {
				row.StoreNote = unreached

				return row, nil
			}
			row.Store = []storeRow{}
			for _, offered := range store {
				i := slices.IndexFunc(row.Installed, func(a appRow) bool { return strings.EqualFold(a.Name, offered.Name) })
				switch {
				case i < 0:
					row.Store = append(row.Store, storeRow{Name: offered.Name, Version: offered.Version, Description: offered.Description, Size: offered.Size})
				case offered.UpdateAvailable || offered.Version != row.Installed[i].Version:
					row.Installed[i].Latest = offered.Version
				default:
				}
			}

			return row, nil
		})
		if _, err := failures(answers); err != nil {
			return nil, appListOut{}, err
		}

		out := appListOut{Servers: []appsOn{}}
		for _, a := range answers {
			row := a.Value
			if a.Err != nil {
				row = appsOn{Server: a.Server.Name, Installed: []appRow{}, Error: a.Err.Error()}
			}
			out.Servers = append(out.Servers, row)
		}

		return nil, out, nil
	})

	type appInstallIn struct {
		writeServerArg

		Name   string `json:"name"              jsonschema:"the app's name. One the store offers is installed from there by this name alone, as app_list with store gives it"`
		URL    string `json:"url,omitempty"     jsonschema:"for an app that is not in the store: the https:// address of its zip file, which the server fetches itself"`
		Path   string `json:"path,omitempty"    jsonschema:"or its zip file on the machine this tool runs on, which is sent to the server: for a server that cannot reach the internet"`
		DryRun bool   `json:"dry_run,omitempty" jsonschema:"change nothing, and answer with what would be"`
	}
	type appInstallOut struct {
		Server  string   `json:"server"`
		Changed bool     `json:"changed"`
		Changes []string `json:"changes"`
		After   *appRow  `json:"after,omitempty" jsonschema:"the app as the server has it now; absent from a dry run"`
		Note    string   `json:"note,omitempty"`
	}
	add(r, writeTool, &mcp.Tool{
		Name:        "app_install",
		Description: "Install a DNS app on a server, or update the one installed under the name to a newer version, keeping its configuration. By its name alone the app comes from the server's maker's store, which the server fetches from over the internet; with url the server fetches a zip file from elsewhere; with path a zip file on this machine is sent to it. An app runs inside the server with everything the server can do, so install only ones that are trusted. What is given must be a zip file: it is checked before anything is sent, because a server keeps a broken upload in a way that stops other servers joining its cluster. On a cluster apps are installed on the primary and reach every node.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in appInstallIn) (*mcp.CallToolResult, appInstallOut, error) {
		name, from, path := strings.TrimSpace(in.Name), strings.TrimSpace(in.URL), strings.TrimSpace(in.Path)
		if name == "" {
			return nil, appInstallOut{}, errors.New("which app: give its name, as app_list with store gives it")
		}
		if from != "" && path != "" {
			return nil, appInstallOut{}, errors.New("give the app's url or its path, not both")
		}
		if from != "" && !strings.HasPrefix(from, "https://") {
			return nil, appInstallOut{}, errors.New("the server fetches an app only over https://")
		}
		srv, err := r.servers.One(in.Server)
		if err != nil {
			return nil, appInstallOut{}, err
		}
		installed, err := installedOn(ctx, srv, name)
		if err != nil {
			return nil, appInstallOut{}, fmt.Errorf("%s: %w", srv.Name, err)
		}
		var file []byte
		source := "the store"
		switch {
		case path != "":
			if file, err = os.ReadFile(path); err != nil { //nolint:gosec // G304: the path is the app the operator asked to be installed
				return nil, appInstallOut{}, fmt.Errorf("reading the app's zip file: %w", err)
			}
			if _, err := zipEntries(file); err != nil {
				return nil, appInstallOut{}, fmt.Errorf("%s is no zip file, which is what an app comes as: %w", path, err)
			}
			source = path
		case from != "":
			source = from
		default:
			store, storeErr := srv.Client.StoreApps(ctx)
			if storeErr != nil {
				return nil, appInstallOut{}, fmt.Errorf("%s could not ask the store for the app: %w. Give the app's url, or its zip file by path", srv.Name, storeErr)
			}
			i := slices.IndexFunc(store, func(a technitium.StoreApp) bool { return strings.EqualFold(a.Name, name) })
			if i < 0 {
				return nil, appInstallOut{}, fmt.Errorf("the store has no app named %q: app_list with store lists what it offers", name)
			}
			name, from = store[i].Name, store[i].URL
			if installed != nil && installed.Version == store[i].Version {
				row := appRowOf(installed)

				return nil, appInstallOut{Server: srv.Name, Changes: []string{}, After: &row, Note: "the server has the store's version of the app already"}, nil
			}
		}

		out := appInstallOut{Server: srv.Name, Changed: true}
		done := &changes{dry: in.DryRun}
		verb := "installed the app %s on %s from %s"
		if installed != nil {
			name, verb = installed.Name, "updated the app %s on %s from %s, keeping its configuration"
		}
		if done.did(verb, name, srv.Name, source) {
			var app *technitium.App
			switch {
			case file != nil && installed != nil:
				app, err = srv.Client.UpdateApp(ctx, name, file)
			case file != nil:
				app, err = srv.Client.InstallApp(ctx, name, file)
			case installed != nil:
				app, err = srv.Client.UpdateAppFrom(ctx, name, from)
			default:
				app, err = srv.Client.InstallAppFrom(ctx, name, from)
			}
			if err != nil {
				return nil, appInstallOut{}, fmt.Errorf("installing %s: %w", name, err)
			}
			row := appRowOf(app)
			out.After = &row
		}
		out.Changes = done.said

		return nil, out, nil
	})

	type appConfigGetIn struct {
		serverArg

		Name string `json:"name" jsonschema:"the app's name, as app_list gives it"`
	}
	type appConfigOn struct {
		Server  string `json:"server"`
		Config  any    `json:"config,omitempty"  jsonschema:"the app's configuration, as JSON when it is JSON and as text otherwise; absent for an app that has none"`
		Missing bool   `json:"missing,omitempty" jsonschema:"this server has no such app installed"`
		Error   string `json:"error,omitempty"`
	}
	type appConfigGetOut struct {
		Name    string        `json:"name"`
		Servers []appConfigOn `json:"servers"`
		Differ  bool          `json:"differ,omitempty" jsonschema:"the servers that have the app do not have it configured alike"`
	}
	add(r, readTool, &mcp.Tool{
		Name:        "app_config_get",
		Description: "An installed app's configuration on each server: the text the app reads its settings from, JSON for most - how long the log of queries is kept, which networks split horizon treats as private, what a failover record checks. Each app's own page in the store says what its configuration means. The servers' are set side by side, with whether they differ.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in appConfigGetIn) (*mcp.CallToolResult, appConfigGetOut, error) {
		name := strings.TrimSpace(in.Name)
		if name == "" {
			return nil, appConfigGetOut{}, errors.New("which app: give its name, as app_list gives it")
		}
		picked, err := r.servers.Pick(in.Server)
		if err != nil {
			return nil, appConfigGetOut{}, err
		}
		type read struct {
			text    string
			missing bool
		}
		answers := ask(ctx, picked, func(ctx context.Context, srv *servers.Server) (read, error) {
			installed, err := installedOn(ctx, srv, name)
			if err != nil || installed == nil {
				return read{missing: installed == nil}, err
			}
			text, err := srv.Client.AppConfig(ctx, installed.Name)

			return read{text: text}, err
		})
		if _, err := failures(answers); err != nil {
			return nil, appConfigGetOut{}, err
		}

		out := appConfigGetOut{Name: name, Servers: []appConfigOn{}}
		var texts []string
		for _, a := range answers {
			row := appConfigOn{Server: a.Server.Name, Missing: a.Value.missing}
			switch {
			case a.Err != nil:
				row.Error = a.Err.Error()
			case a.Value.missing:
			default:
				texts = append(texts, a.Value.text)
				var parsed any
				if a.Value.text != "" && json.Unmarshal([]byte(a.Value.text), &parsed) == nil {
					row.Config = parsed
				} else if a.Value.text != "" {
					row.Config = a.Value.text
				}
			}
			out.Servers = append(out.Servers, row)
		}
		if len(texts) == 0 {
			return nil, appConfigGetOut{}, fmt.Errorf("no server asked has an app named %s installed: app_list names the apps", name)
		}
		out.Differ = slices.ContainsFunc(texts, func(text string) bool { return strings.TrimSpace(text) != strings.TrimSpace(texts[0]) })

		return nil, out, nil
	})

	type appConfigSetIn struct {
		writeServerArg

		Name   string `json:"name"              jsonschema:"the app's name, as app_list gives it"`
		Config string `json:"config"            jsonschema:"the app's whole configuration, as text: it replaces the one there is, so read it first (app_config_get), change what is wanted and give all of it back"`
		DryRun bool   `json:"dry_run,omitempty" jsonschema:"change nothing, and answer with what would be"`
	}
	type appConfigSetOut struct {
		Server  string   `json:"server"`
		Changed bool     `json:"changed"`
		Changes []string `json:"changes"`
		Before  string   `json:"before,omitempty" jsonschema:"the configuration as it was, which is what to give back to undo the change"`
		Note    string   `json:"note,omitempty"`
	}
	add(r, writeTool, &mcp.Tool{
		Name:        "app_config_set",
		Description: "Write an installed app's configuration on a server, whole: it replaces what was there and takes effect at once. Read it first (app_config_get), change the part wanted, and give all of it back. The answer holds the configuration as it was, to put back if the app does not take the new one. A configuration that was JSON must stay JSON: text that is not is refused, since the app would stop working. On a cluster an app is configured on the primary and reaches every node.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in appConfigSetIn) (*mcp.CallToolResult, appConfigSetOut, error) {
		name := strings.TrimSpace(in.Name)
		if name == "" {
			return nil, appConfigSetOut{}, errors.New("which app: give its name, as app_list gives it")
		}
		srv, err := r.servers.One(in.Server)
		if err != nil {
			return nil, appConfigSetOut{}, err
		}
		installed, err := installedOn(ctx, srv, name)
		if err != nil {
			return nil, appConfigSetOut{}, fmt.Errorf("%s: %w", srv.Name, err)
		}
		if installed == nil {
			return nil, appConfigSetOut{}, fmt.Errorf("%s has no app named %s installed: app_list names its apps", srv.Name, name)
		}
		before, err := srv.Client.AppConfig(ctx, installed.Name)
		if err != nil {
			return nil, appConfigSetOut{}, fmt.Errorf("reading the app's configuration: %w", err)
		}
		if json.Valid([]byte(before)) && strings.TrimSpace(in.Config) != "" && !json.Valid([]byte(in.Config)) {
			return nil, appConfigSetOut{}, errors.New("the app's configuration is JSON and what was given is not: it would stop the app working. Nothing was changed")
		}

		out := appConfigSetOut{Server: srv.Name, Changes: []string{}, Before: before}
		if strings.TrimSpace(before) == strings.TrimSpace(in.Config) {
			out.Note = "the app has that configuration already"

			return nil, out, nil
		}
		out.Changed = true
		done := &changes{dry: in.DryRun}
		if done.did("set the configuration of the app %s on %s, %d characters in place of %d", installed.Name, srv.Name, len(in.Config), len(before)) {
			if err := srv.Client.SetAppConfig(ctx, installed.Name, in.Config); err != nil {
				return nil, appConfigSetOut{}, fmt.Errorf("writing the configuration: %w", err)
			}
			after, err := srv.Client.AppConfig(ctx, installed.Name)
			if err != nil {
				return nil, appConfigSetOut{}, fmt.Errorf("the configuration was written and could not be read back: %w", err)
			}
			if strings.TrimSpace(after) != strings.TrimSpace(in.Config) {
				out.Note = "the server said ok and the app's configuration reads back otherwise: app_config_get shows it"
			}
		}
		out.Changes = done.said

		return nil, out, nil
	})

	type appDeleteIn struct {
		writeServerArg

		Name   string `json:"name"              jsonschema:"the app's name, as app_list gives it"`
		DryRun bool   `json:"dry_run,omitempty" jsonschema:"change nothing, and answer with what would be"`
	}
	type appDeleteOut struct {
		Server  string   `json:"server"`
		Changed bool     `json:"changed"`
		Changes []string `json:"changes"`
		Was     *appRow  `json:"was,omitempty"  jsonschema:"the app as it was installed"`
		Note    string   `json:"note,omitempty"`
	}
	add(r, deleteTool, &mcp.Tool{
		Name:        "app_delete",
		Description: "Uninstall a DNS app from a server, with its configuration and whatever it kept: uninstalling the app that keeps the log of queries deletes that log. Records in the zones that were answered by the app stay where they are and answer nothing from then on. On a cluster apps are uninstalled on the primary.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in appDeleteIn) (*mcp.CallToolResult, appDeleteOut, error) {
		name := strings.TrimSpace(in.Name)
		if name == "" {
			return nil, appDeleteOut{}, errors.New("which app: give its name, as app_list gives it")
		}
		srv, err := r.servers.One(in.Server)
		if err != nil {
			return nil, appDeleteOut{}, err
		}
		installed, err := installedOn(ctx, srv, name)
		if err != nil {
			return nil, appDeleteOut{}, fmt.Errorf("%s: %w", srv.Name, err)
		}
		out := appDeleteOut{Server: srv.Name, Changes: []string{}}
		if installed == nil {
			// the server uninstalls an app it does not have without a word, so it is said here
			out.Note = "the server has no such app installed: there is nothing to uninstall"

			return nil, out, nil
		}

		was := appRowOf(installed)
		out.Changed, out.Was = true, &was
		if was.LogsHere {
			out.Note = "this app kept the log of queries, which went with it: there is no log of queries to search on this server until one is installed again"
		}
		done := &changes{dry: in.DryRun}
		if done.did("uninstalled the app %s %s from %s", installed.Name, installed.Version, srv.Name) {
			if err := srv.Client.UninstallApp(ctx, installed.Name); err != nil {
				return nil, appDeleteOut{}, fmt.Errorf("uninstalling %s: %w", installed.Name, err)
			}
			if still, err := installedOn(ctx, srv, installed.Name); err == nil && still != nil {
				return nil, appDeleteOut{}, fmt.Errorf("the server said ok and %s still has the app %s installed", srv.Name, installed.Name)
			}
		}
		out.Changes = done.said

		return nil, out, nil
	})
}
