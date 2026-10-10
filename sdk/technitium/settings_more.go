package technitium

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// SettingNames are the settings the server takes, by the names its API
// knows them under: what SetSettings may be given. The tests hold the list
// against the API document.
var SettingNames = []string{
	"dnsServerDomain",
	"dnsServerLocalEndPoints",
	"dnsServerIPv4SourceAddresses",
	"dnsServerIPv6SourceAddresses",
	"defaultRecordTtl",
	"defaultNsRecordTtl",
	"defaultSoaRecordTtl",
	"defaultResponsiblePerson",
	"useSoaSerialDateScheme",
	"minSoaRefresh",
	"minSoaRetry",
	"zoneTransferAllowedNetworks",
	"notifyAllowedNetworks",
	"dnsServerEnableCheckForUpdate",
	"dnsAppsEnableAutomaticUpdate",
	"ipv6Mode",
	"enableUdpSocketPool",
	"socketPoolExcludedPorts",
	"udpPayloadSize",
	"dnssecValidation",
	"eDnsClientSubnet",
	"eDnsClientSubnetIPv4PrefixLength",
	"eDnsClientSubnetIPv6PrefixLength",
	"eDnsClientSubnetIpv4Override",
	"eDnsClientSubnetIpv6Override",
	"qpmPrefixLimitsIPv4",
	"qpmPrefixLimitsIPv6",
	"qpmLimitSampleMinutes",
	"qpmLimitUdpTruncationPercentage",
	"qpmLimitBypassList",
	"clientTimeout",
	"tcpSendTimeout",
	"tcpReceiveTimeout",
	"quicIdleTimeout",
	"quicMaxInboundStreams",
	"listenBacklog",
	"udpSendBufferSizeKB",
	"udpReceiveBufferSizeKB",
	"maxConcurrentResolutionsPerCore",
	"webServiceLocalAddresses",
	"webServiceHttpPort",
	"webServiceEnableHttpUnixSocket",
	"webServiceHttpUnixSocket",
	"webServiceEnableTlsUnixSocket",
	"webServiceTlsUnixSocket",
	"webServiceEnableTls",
	"webServiceEnableHttp3",
	"webServiceHttpToTlsRedirect",
	"webServiceTlsPort",
	"webServiceReverseProxyAddresses",
	"webServiceUseSelfSignedTlsCertificate",
	"webServiceTlsCertificatePath",
	"webServiceTlsCertificatePassword",
	"webServiceRealIpHeader",
	"webServiceCspFrameAncestorsHeader",
	"enableEDnsClientSubnetSourceAddress",
	"enableDnsOverUdpProxy",
	"enableDnsOverTcpProxy",
	"enableDnsOverHttp",
	"enableDnsOverHttpUnixSocket",
	"enableDnsOverHttpsUnixSocket",
	"enableDnsOverTls",
	"enableDnsOverHttps",
	"enableDnsOverQuic",
	"enableDnsOverHttpHelpRedirect",
	"dnsOverUdpProxyPort",
	"dnsOverTcpProxyPort",
	"dnsOverHttpPort",
	"dnsOverHttpUnixSocket",
	"dnsOverHttpsUnixSocket",
	"dnsOverTlsPort",
	"dnsOverHttpsPort",
	"dnsOverQuicPort",
	"dnsReverseProxyNetworkACL",
	"dnsTlsCertificatePath",
	"dnsTlsCertificatePassword",
	"dnsOverHttpRealIpHeader",
	"tsigKeys",
	"recursion",
	"recursionNetworkACL",
	"randomizeName",
	"qnameMinimization",
	"locallyServedDnsZones",
	"resolverRetries",
	"resolverTimeout",
	"resolverConcurrency",
	"resolverMaxStackCount",
	"saveCache",
	"serveStale",
	"serveStaleTtl",
	"serveStaleAnswerTtl",
	"serveStaleResetTtl",
	"serveStaleMaxWaitTime",
	"cacheMinimumRecordTtl",
	"cacheMaximumRecordTtl",
	"cacheNegativeRecordTtl",
	"cacheFailureRecordTtl",
	"enableCachePrefetch",
	"cachePrefetchEligibility",
	"cachePrefetchTrigger",
	"enableBlocking",
	"allowTxtBlockingReport",
	"blockingBypassList",
	"blockingType",
	"blockingAnswerTtl",
	"customBlockingAddresses",
	"blockListUrls",
	"blockListUpdateIntervalHours",
	"proxyType",
	"proxyAddress",
	"proxyPort",
	"proxyUsername",
	"proxyPassword",
	"proxyBypass",
	"forwarders",
	"forwarderProtocol",
	"concurrentForwarding",
	"forwarderRetries",
	"forwarderTimeout",
	"forwarderConcurrency",
	"loggingType",
	"enableLogging",
	"ignoreResolverLogs",
	"logQueries",
	"noStackTrace",
	"useLocalTime",
	"logFolder",
	"maxLogFileDays",
	"enableInMemoryStats",
	"maxStatFileDays",
}

// SettingsNeverRead are the settings the server takes and never gives back
// under the name it takes them by: the two certificate passwords, which it
// does not give at all, and the proxy, which it gives as one thing under
// proxy. Any other setting a server does not answer with is one its version
// does not have, as 15.5 does not have enableCachePrefetch.
var SettingsNeverRead = []string{"webServiceTlsCertificatePassword", "dnsTlsCertificatePassword", "proxyType", "proxyAddress", "proxyPort", "proxyUsername", "proxyPassword", "proxyBypass"}

// secretSetting reports whether a setting, or a field of what the server
// answers about its settings, holds something secret: a password, or a
// key's shared secret.
func secretSetting(name string) bool {
	name = strings.ToLower(name)

	return strings.HasSuffix(name, "password") || strings.HasSuffix(name, "secret")
}

// withoutSecrets takes what is secret out of the settings as the server
// answers them, however deep it sits: a key keeps its name and loses its
// shared secret.
func withoutSecrets(value any) any {
	switch v := value.(type) {
	case map[string]any:
		for name, inner := range v {
			if secretSetting(name) {
				delete(v, name)

				continue
			}
			v[name] = withoutSecrets(inner)
		}
	case []any:
		for i := range v {
			v[i] = withoutSecrets(v[i])
		}
	default:
	}

	return value
}

// AllSettings reads every setting the server has, each under the name the
// API gives it, where Settings reads the part this client knows by type.
// What is secret is left out: no password, and no key's shared secret.
func (c *Client) AllSettings(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	if err := c.read(ctx, "settings/get", nil, &out); err != nil {
		return nil, err
	}
	withoutSecrets(out)

	return out, nil
}

// SetSettings sets settings by name, each to a value written as the API
// takes it - true or false, a number, a list with commas between, a table
// with bars - and returns every setting as it now stands, without what is
// secret. Only the settings given change. A name the API does not know is
// refused here, since the server passes one over without a word.
//
// A server passes over a setting a later version brought the same way. That
// is an error here once it has answered, and the settings come back with it:
// whatever else was sent in the same call is set.
//
// Some settings restart the server's console or its DNS service when they
// change, and for that moment it answers nothing.
func (c *Client) SetSettings(ctx context.Context, values map[string]string) (map[string]any, error) {
	if len(values) == 0 {
		return nil, errors.New("settings/set: which setting: nothing was given to set")
	}
	params := url.Values{}
	for name, value := range values {
		if !slices.Contains(SettingNames, name) {
			return nil, fmt.Errorf("settings/set: there is no setting named %q: the names are the API's own, as AllSettings gives them", name)
		}
		params.Set(name, value)
	}

	var out map[string]any
	if err := c.write(ctx, "settings/set", params, &out); err != nil {
		return nil, err
	}
	withoutSecrets(out)

	var passedOver []string
	for name := range values {
		if _, has := out[name]; !has && !slices.Contains(SettingsNeverRead, name) {
			passedOver = append(passedOver, name)
		}
	}
	if len(passedOver) > 0 {
		slices.Sort(passedOver)

		return out, fmt.Errorf("settings/set: the server (version %v) said ok and has no setting named %s: a later version of the server brought it. Anything else sent with it is set", out["version"], strings.Join(passedOver, ", "))
	}

	return out, nil
}

// TSIGKeyNames lists the transfer keys the server has, by name.
func (c *Client) TSIGKeyNames(ctx context.Context) ([]string, error) {
	var out struct {
		Names []string `json:"tsigKeyNames"`
	}
	if err := c.read(ctx, "settings/getTsigKeyNames", nil, &out); err != nil {
		return nil, err
	}

	return out.Names, nil
}

// BackupItems are the parts of a server a backup can hold, and a restore
// can put back.
type BackupItems struct {
	// AuthConfig is the accounts, groups, permissions and tokens
	AuthConfig bool
	// ClusterConfig is the server's place in a cluster
	ClusterConfig bool
	// WebServiceSettings is how the console is served
	WebServiceSettings bool
	// DNSSettings is the DNS settings, with the certificates kept in the
	// server's own folder
	DNSSettings bool
	LogSettings bool
	Zones       bool
	// AllowedZones and BlockedZones are the server's own two lists, and
	// BlockLists what it has fetched of the lists it follows
	AllowedZones bool
	BlockedZones bool
	BlockLists   bool
	Apps         bool
	// Scopes is the DHCP scopes with their leases
	Scopes bool
	Stats  bool
	Logs   bool
}

// Everything is every part of a server a backup can hold.
func Everything() BackupItems {
	return BackupItems{AuthConfig: true, ClusterConfig: true, WebServiceSettings: true, DNSSettings: true, LogSettings: true, Zones: true, AllowedZones: true, BlockedZones: true, BlockLists: true, Apps: true, Scopes: true, Stats: true, Logs: true}
}

func (b BackupItems) params(path string) (url.Values, error) {
	params := url.Values{}
	for name, wanted := range map[string]bool{"authConfig": b.AuthConfig, "clusterConfig": b.ClusterConfig, "webServiceSettings": b.WebServiceSettings, "dnsSettings": b.DNSSettings, "logSettings": b.LogSettings, "zones": b.Zones, "allowedZones": b.AllowedZones, "blockedZones": b.BlockedZones, "blockLists": b.BlockLists, "apps": b.Apps, "scopes": b.Scopes, "stats": b.Stats, "logs": b.Logs} {
		if wanted {
			params.Set(name, yes)
		}
	}
	if len(params) == 0 {
		return nil, errors.New(path + ": which parts of the server: none was asked for")
	}

	return params, nil
}

// Backup reads the parts of the server asked for as one zip file. A backup
// with the accounts, the settings or the zones in it holds what is secret
// on the server - password hashes, tokens, keys - and is kept as carefully.
func (c *Client) Backup(ctx context.Context, items BackupItems) ([]byte, error) {
	params, err := items.params("settings/backup")
	if err != nil {
		return nil, err
	}

	return c.readFile(ctx, "settings/backup", params)
}

// Restore puts the parts asked for back from a backup's zip file, writing
// over what the server has of them, and returns the settings as they now
// stand. With deleteExisting, what the server has of a part and the backup
// has not is deleted too. Restoring the accounts can end the session the
// client works under.
func (c *Client) Restore(ctx context.Context, items BackupItems, deleteExisting bool, zip []byte) (*Settings, error) {
	params, err := items.params("settings/restore")
	if err != nil {
		return nil, err
	}
	if !isZip(zip) {
		return nil, errors.New("settings/restore: a backup is a zip file, and what was given is not one")
	}
	if deleteExisting {
		params.Set("deleteExistingFiles", yes)
	}

	var out Settings
	if err := c.upload(ctx, "settings/restore", params, file{name: "backup.zip", data: zip}, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// DefaultTSIGAlgorithm is the algorithm a transfer key is made with when
// none is asked for.
const DefaultTSIGAlgorithm = "hmac-sha256"

// tsigKey is a transfer key whole, shared secret and all. It is read only
// to be sent back: the settings take the keys as one list, so one cannot be
// added or taken away without the others being sent again as they are.
// Nothing outside this file is given one.
type tsigKey struct {
	Name      string `json:"keyName"`
	Secret    string `json:"sharedSecret"`
	Algorithm string `json:"algorithmName"`
}

// writeTSIGKeys sets the server's transfer keys to a list.
func (c *Client) writeTSIGKeys(ctx context.Context, keys []tsigKey) error {
	// the API's word for none
	table := "false"
	if len(keys) > 0 {
		cells := make([]string, 0, 3*len(keys))
		for _, k := range keys {
			cells = append(cells, k.Name, k.Secret, k.Algorithm)
		}
		table = strings.Join(cells, "|")
	}

	return c.write(ctx, "settings/set", url.Values{"tsigKeys": {table}}, nil)
}

// readTSIGKeys reads the server's transfer keys whole.
func (c *Client) readTSIGKeys(ctx context.Context) ([]tsigKey, error) {
	var out struct {
		Keys []tsigKey `json:"tsigKeys"`
	}
	if err := c.read(ctx, "settings/get", nil, &out); err != nil {
		return nil, err
	}

	return out.Keys, nil
}

// SetTSIGKey adds a transfer key to the server, or changes the one there is
// under the name, leaving every other key as it is. The shared secret is
// base64, as the two ends of a transfer are both given it; with none the
// server makes one up, which only this server then has. The algorithm is
// hmac-sha256 unless another is named.
func (c *Client) SetTSIGKey(ctx context.Context, name, sharedSecret, algorithm string) error {
	if name == "" || strings.ContainsAny(name+sharedSecret+algorithm, "|") {
		return errors.New("settings/set: a transfer key has a name, and neither it nor its secret has a | in it")
	}
	if algorithm == "" {
		algorithm = DefaultTSIGAlgorithm
	}
	keys, err := c.readTSIGKeys(ctx)
	if err != nil {
		return err
	}
	replaced := false
	for i := range keys {
		if strings.EqualFold(keys[i].Name, name) {
			keys[i], replaced = tsigKey{Name: keys[i].Name, Secret: sharedSecret, Algorithm: algorithm}, true
		}
	}
	if !replaced {
		keys = append(keys, tsigKey{Name: name, Secret: sharedSecret, Algorithm: algorithm})
	}

	return c.writeTSIGKeys(ctx, keys)
}

// DeleteTSIGKey takes a transfer key off the server, leaving every other
// as it is. A key that is not there is no error; one a zone still uses the
// server refuses to lose.
func (c *Client) DeleteTSIGKey(ctx context.Context, name string) error {
	if name == "" {
		return errors.New("settings/set: which transfer key")
	}
	keys, err := c.readTSIGKeys(ctx)
	if err != nil {
		return err
	}
	kept := keys[:0]
	for _, k := range keys {
		if !strings.EqualFold(k.Name, name) {
			kept = append(kept, k)
		}
	}
	if len(kept) == len(keys) {
		return nil
	}

	return c.writeTSIGKeys(ctx, kept)
}
