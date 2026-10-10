package technitium

import "context"

// Settings is how a server is set up: the part of its settings this client
// reads. Nothing secret is among them - a TSIG key is its name and its
// algorithm, never its shared secret, and no certificate or proxy password
// is read at all - so nothing that prints the settings can print a
// credential.
type Settings struct {
	Version string `json:"version"`
	Domain  string `json:"dnsServerDomain"`

	// LocalEndPoints are the addresses the server answers DNS on
	LocalEndPoints []string `json:"dnsServerLocalEndPoints"`

	DefaultRecordTTL   int `json:"defaultRecordTtl"`
	DefaultNSRecordTTL int `json:"defaultNsRecordTtl"`
	DefaultSOATTL      int `json:"defaultSoaRecordTtl"`

	// ZoneTransferAllowedNetworks and NotifyAllowedNetworks are who may
	// transfer any zone from the server, and send it a notify, whatever a
	// zone's own settings say
	ZoneTransferAllowedNetworks []string `json:"zoneTransferAllowedNetworks"`
	NotifyAllowedNetworks       []string `json:"notifyAllowedNetworks"`

	CheckForUpdate   bool `json:"dnsServerEnableCheckForUpdate"`
	AppsAutoUpdate   bool `json:"dnsAppsEnableAutomaticUpdate"`
	DNSSECValidation bool `json:"dnssecValidation"`

	// Recursion is who the server resolves other people's names for: Deny,
	// Allow, AllowOnlyForPrivateNetworks or UseSpecifiedNetworkACL, with
	// RecursionNetworkACL for the last
	Recursion           string   `json:"recursion"`
	RecursionNetworkACL []string `json:"recursionNetworkACL"`
	QNameMinimization   bool     `json:"qnameMinimization"`

	// Forwarders are the name servers the server sends what it does not
	// hold to; none is resolving from the root itself
	Forwarders        []string `json:"forwarders"`
	ForwarderProtocol string   `json:"forwarderProtocol"`
	// Proxy is the proxy the server resolves through, nil for none
	Proxy *struct {
		Type    string `json:"type"`
		Address string `json:"address"`
		Port    int    `json:"port"`
	} `json:"proxy"`

	TSIGKeys []TSIGKey `json:"tsigKeys"`

	SaveCache              bool `json:"saveCache"`
	ServeStale             bool `json:"serveStale"`
	CacheMaximumEntries    int  `json:"cacheMaximumEntries"`
	CacheMinimumRecordTTL  int  `json:"cacheMinimumRecordTtl"`
	CacheMaximumRecordTTL  int  `json:"cacheMaximumRecordTtl"`
	CacheNegativeRecordTTL int  `json:"cacheNegativeRecordTtl"`

	EnableBlocking               bool     `json:"enableBlocking"`
	BlockingType                 string   `json:"blockingType"`
	CustomBlockingAddresses      []string `json:"customBlockingAddresses"`
	BlockListURLs                []string `json:"blockListUrls"`
	BlockListUpdateIntervalHours int      `json:"blockListUpdateIntervalHours"`
	// BlockListNextUpdatedOn is when the lists are next fetched, in UTC
	BlockListNextUpdatedOn string `json:"blockListNextUpdatedOn"`
	// TemporaryDisableBlockingTill is when blocking that was switched off
	// for a while comes back on, in UTC; "" when it was not
	TemporaryDisableBlockingTill string `json:"temporaryDisableBlockingTill"`
	// BlockingBypassList are the clients nothing is blocked for, as
	// addresses and networks
	BlockingBypassList []string `json:"blockingBypassList"`

	WebServiceHTTPPort          int  `json:"webServiceHttpPort"`
	WebServiceEnableTLS         bool `json:"webServiceEnableTls"`
	WebServiceTLSPort           int  `json:"webServiceTlsPort"`
	WebServiceHTTPToTLSRedirect bool `json:"webServiceHttpToTlsRedirect"`
	WebServiceUseSelfSignedCert bool `json:"webServiceUseSelfSignedTlsCertificate"`

	EnableDNSOverUDPProxy bool `json:"enableDnsOverUdpProxy"`
	EnableDNSOverTCPProxy bool `json:"enableDnsOverTcpProxy"`
	EnableDNSOverHTTP     bool `json:"enableDnsOverHttp"`
	EnableDNSOverTLS      bool `json:"enableDnsOverTls"`
	EnableDNSOverHTTPS    bool `json:"enableDnsOverHttps"`
	EnableDNSOverHTTP3    bool `json:"enableDnsOverHttp3"`
	EnableDNSOverQUIC     bool `json:"enableDnsOverQuic"`

	LoggingType    string `json:"loggingType"`
	LogQueries     bool   `json:"logQueries"`
	UseLocalTime   bool   `json:"useLocalTime"`
	LogFolder      string `json:"logFolder"`
	MaxLogFileDays int    `json:"maxLogFileDays"`
}

// TSIGKey is a transfer key by its name: its secret is never read.
type TSIGKey struct {
	Name      string `json:"keyName"`
	Algorithm string `json:"algorithmName"`
}

// Settings reads how the server is set up.
func (c *Client) Settings(ctx context.Context) (*Settings, error) {
	var out Settings
	if err := c.read(ctx, "settings/get", nil, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// App is a DNS app installed on the server.
type App struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// Parts are what the app adds to the server, each by its class
	Parts []struct {
		ClassPath string `json:"classPath"`
		// IsQueryLogger is the part being given every query to log, and
		// IsQueryLogs its log being one that can be searched
		IsQueryLogger bool `json:"isQueryLogger"`
		IsQueryLogs   bool `json:"isQueryLogs"`
	} `json:"dnsApps"`
}

// LogsQueries reports whether the app keeps a log of queries that can be
// searched.
func (a *App) LogsQueries() bool {
	_, logs := a.QueryLog()

	return logs
}

// QueryLog is the class of the app's part that keeps a searchable log of
// queries, which a search of the log names it by; false for an app with none.
func (a *App) QueryLog() (classPath string, ok bool) {
	for _, part := range a.Parts {
		if part.IsQueryLogs || part.IsQueryLogger {
			return part.ClassPath, true
		}
	}

	return "", false
}

// Apps lists the DNS apps installed on the server.
func (c *Client) Apps(ctx context.Context) ([]App, error) {
	var out struct {
		Apps []App `json:"apps"`
	}
	if err := c.read(ctx, "apps/list", nil, &out); err != nil {
		return nil, err
	}

	return out.Apps, nil
}
