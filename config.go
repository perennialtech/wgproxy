package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type options struct {
	configDir             string
	proxyAddr             string
	adminAddr             string
	healthURL             string
	healthInterval        time.Duration
	healthTimeout         time.Duration
	dialTimeout           time.Duration
	responseHeaderTimeout time.Duration
	shutdownTimeout       time.Duration
	maxActive             int
}

func defaultOptions() options {
	return options{
		configDir:             "/etc/wgproxy/wireguard",
		proxyAddr:             "0.0.0.0:8080",
		adminAddr:             "127.0.0.1:9090",
		healthURL:             "https://www.gstatic.com/generate_204",
		healthInterval:        30 * time.Second,
		healthTimeout:         10 * time.Second,
		dialTimeout:           15 * time.Second,
		responseHeaderTimeout: 30 * time.Second,
		shutdownTimeout:       15 * time.Second,
		maxActive:             256,
	}
}

func loadOptions() (options, error) {
	o := defaultOptions()

	for name, target := range map[string]*string{
		"WG_CONFIG_DIR":   &o.configDir,
		"PROXY_ADDR":      &o.proxyAddr,
		"ADMIN_ADDR":      &o.adminAddr,
		"HEALTHCHECK_URL": &o.healthURL,
	} {
		if value, exists := os.LookupEnv(name); exists {
			if value == "" {
				return o, fmt.Errorf("%s must not be empty", name)
			}

			*target = value
		}
	}

	for name, target := range map[string]*time.Duration{
		"HEALTHCHECK_INTERVAL":    &o.healthInterval,
		"HEALTHCHECK_TIMEOUT":     &o.healthTimeout,
		"DIAL_TIMEOUT":            &o.dialTimeout,
		"RESPONSE_HEADER_TIMEOUT": &o.responseHeaderTimeout,
		"SHUTDOWN_TIMEOUT":        &o.shutdownTimeout,
	} {
		if value, exists := os.LookupEnv(name); exists {
			d, err := time.ParseDuration(value)
			if err != nil || d <= 0 {
				return o, fmt.Errorf("%s must be a positive duration", name)
			}

			*target = d
		}
	}

	if value, exists := os.LookupEnv("MAX_ACTIVE"); exists {
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 {
			return o, fmt.Errorf("MAX_ACTIVE must be a positive integer")
		}

		o.maxActive = n
	}

	if err := validateListenAddress(o.proxyAddr); err != nil {
		return o, fmt.Errorf("PROXY_ADDR: %w", err)
	}

	if err := validateAdminAddress(o.adminAddr); err != nil {
		return o, err
	}

	u, err := url.Parse(o.healthURL)
	if err != nil || u == nil {
		return o, fmt.Errorf("HEALTHCHECK_URL must be an absolute HTTP or HTTPS URL")
	}

	if (u.Scheme != "http" && u.Scheme != "https") ||
		u.Host == "" || u.User != nil || u.Fragment != "" {
		return o, fmt.Errorf("HEALTHCHECK_URL must be an absolute HTTP or HTTPS URL without credentials or a fragment")
	}

	if _, err := urlDestination(u); err != nil {
		return o, fmt.Errorf("HEALTHCHECK_URL: %w", err)
	}

	return o, nil
}

func validateListenAddress(address string) error {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("expected host:port")
	}

	if _, err := parsePort(port); err != nil {
		return err
	}

	return nil
}

func validateAdminAddress(address string) error {
	host, _, err := parseAuthority(address)
	if err != nil {
		return fmt.Errorf("ADMIN_ADDR: %w", err)
	}

	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsLoopback() {
		return fmt.Errorf("ADMIN_ADDR must use a numeric loopback address")
	}

	return nil
}

func parsePort(value string) (uint16, error) {
	for _, char := range value {
		if char < '0' || char > '9' {
			return 0, fmt.Errorf("port must be an integer between 1 and 65535")
		}
	}

	n, err := strconv.ParseUint(value, 10, 16)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("port must be an integer between 1 and 65535")
	}

	return uint16(n), nil
}

func parseAuthority(address string) (string, uint16, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" {
		return "", 0, fmt.Errorf("expected a nonempty host and explicit port")
	}

	if strings.ContainsAny(host, " \t\r\n/?#@\\%") {
		return "", 0, fmt.Errorf("invalid destination host")
	}

	if strings.Contains(host, ":") {
		if ip, err := netip.ParseAddr(host); err != nil || !ip.Is6() {
			return "", 0, fmt.Errorf("invalid IPv6 destination")
		}
	}

	n, err := parsePort(port)
	if err != nil {
		return "", 0, err
	}

	return host, n, nil
}

func urlDestination(u *url.URL) (string, error) {
	if u.Host == "" || u.Hostname() == "" || strings.HasSuffix(u.Host, ":") {
		return "", fmt.Errorf("invalid URL authority")
	}

	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}

	address := net.JoinHostPort(u.Hostname(), port)
	if _, _, err := parseAuthority(address); err != nil {
		return "", err
	}

	return address, nil
}

type profileConfig struct {
	id           string
	privateKey   string
	publicKey    string
	presharedKey string
	addresses    []netip.Addr
	dns          []netip.Addr
	allowedIPs   []netip.Prefix
	endpointHost string
	endpointPort uint16
	keepalive    uint16
	mtu          int
	ipv6         bool
}

func loadConfigs(directory string) ([]profileConfig, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("read configuration directory: %w", err)
	}

	var configs []profileConfig

	// os.ReadDir returns entries sorted by filename.
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}

		path := filepath.Join(directory, entry.Name())

		file, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", entry.Name(), err)
		}

		config, parseErr := parseConfig(file)
		closeErr := file.Close()

		if parseErr != nil {
			return nil, fmt.Errorf("%s: %w", entry.Name(), parseErr)
		}

		if closeErr != nil {
			return nil, fmt.Errorf("close %s: %w", entry.Name(), closeErr)
		}

		config.id = strings.TrimSuffix(entry.Name(), ".conf")
		if config.id == "" {
			return nil, fmt.Errorf("configuration filename must have a nonempty profile ID")
		}

		configs = append(configs, config)
	}

	if len(configs) == 0 {
		return nil, fmt.Errorf("no .conf files in %s", directory)
	}

	return configs, nil
}

func parseConfig(reader io.Reader) (profileConfig, error) {
	config := profileConfig{mtu: 1420}
	fields := make(map[string][]string)
	sections := make(map[string]bool)
	section := ""
	lineNumber := 0
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		lineNumber++
		line, _, _ := strings.Cut(scanner.Text(), "#")
		line = strings.TrimSpace(line)

		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "[") {
			if line != "[Interface]" && line != "[Peer]" {
				return config, fmt.Errorf("line %d: unsupported section", lineNumber)
			}

			section = strings.Trim(line, "[]")
			if sections[section] {
				return config, fmt.Errorf("line %d: repeated %s section", lineNumber, section)
			}

			sections[section] = true

			continue
		}

		key, value, found := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		if !found || value == "" || section == "" {
			return config, fmt.Errorf("line %d: expected a nonempty key=value inside a section", lineNumber)
		}

		if !supportedField(section, key) {
			return config, fmt.Errorf("line %d: unsupported directive %s.%s", lineNumber, section, key)
		}

		name := section + "." + key

		repeatable := key == "Address" || key == "DNS" || key == "AllowedIPs"
		if len(fields[name]) != 0 && !repeatable {
			return config, fmt.Errorf("line %d: duplicate directive %s", lineNumber, name)
		}

		if repeatable {
			for _, item := range strings.Split(value, ",") {
				item = strings.TrimSpace(item)
				if item == "" {
					return config, fmt.Errorf("line %d: empty item in %s", lineNumber, name)
				}

				fields[name] = append(fields[name], item)
			}
		} else {
			fields[name] = []string{value}
		}
	}

	if err := scanner.Err(); err != nil {
		return config, fmt.Errorf("read configuration: %w", err)
	}

	if !sections["Interface"] || !sections["Peer"] {
		return config, fmt.Errorf("exactly one Interface and one Peer section are required")
	}

	for _, name := range []string{
		"Interface.PrivateKey", "Interface.Address", "Interface.DNS",
		"Peer.PublicKey", "Peer.AllowedIPs", "Peer.Endpoint",
	} {
		if len(fields[name]) == 0 {
			return config, fmt.Errorf("missing %s", name)
		}
	}

	for name, target := range map[string]*string{
		"Interface.PrivateKey": &config.privateKey,
		"Peer.PublicKey":       &config.publicKey,
		"Peer.PresharedKey":    &config.presharedKey,
	} {
		if values := fields[name]; len(values) != 0 {
			key, err := base64.StdEncoding.DecodeString(values[0])
			if err != nil || len(key) != 32 {
				return config, fmt.Errorf("%s must be a base64-encoded 32-byte key", name)
			}

			*target = hex.EncodeToString(key)
		}
	}

	hasIPv4 := false
	hasIPv6 := false

	for _, value := range fields["Interface.Address"] {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Addr().Is4In6() ||
			prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() {
			return config, fmt.Errorf("invalid Interface.Address")
		}

		address := prefix.Addr()
		config.addresses = append(config.addresses, address)
		hasIPv4 = hasIPv4 || address.Is4()
		hasIPv6 = hasIPv6 || address.Is6()
	}

	fullIPv4 := false
	fullIPv6 := false

	for _, value := range fields["Peer.AllowedIPs"] {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Addr().Is4In6() {
			return config, fmt.Errorf("invalid Peer.AllowedIPs")
		}

		prefix = prefix.Masked()
		config.allowedIPs = append(config.allowedIPs, prefix)
		fullIPv4 = fullIPv4 || (prefix.Addr().Is4() && prefix.Bits() == 0)
		fullIPv6 = fullIPv6 || (prefix.Addr().Is6() && prefix.Bits() == 0)
	}

	if !hasIPv4 || !fullIPv4 {
		return config, fmt.Errorf("an IPv4 interface address and 0.0.0.0/0 in AllowedIPs are required")
	}

	config.ipv6 = hasIPv6 && fullIPv6

	for _, value := range fields["Interface.DNS"] {
		address, err := netip.ParseAddr(value)
		if err != nil || address.Zone() != "" || address.IsUnspecified() ||
			address.IsMulticast() || address.Is4In6() {
			return config, fmt.Errorf("Interface.DNS entries must be unscoped unicast IP addresses")
		}

		if address.Is6() && !config.ipv6 {
			return config, fmt.Errorf("an IPv6 DNS server requires an IPv6 address and ::/0")
		}

		config.dns = append(config.dns, address)
	}

	host, port, err := parseAuthority(fields["Peer.Endpoint"][0])
	if err != nil {
		return config, fmt.Errorf("Peer.Endpoint: %w", err)
	}

	config.endpointHost = host
	config.endpointPort = port

	if values := fields["Peer.PersistentKeepalive"]; len(values) != 0 {
		n, err := strconv.ParseUint(values[0], 10, 16)
		if err != nil {
			return config, fmt.Errorf("PersistentKeepalive must be between 0 and 65535")
		}

		config.keepalive = uint16(n)
	}

	if values := fields["Interface.ListenPort"]; len(values) != 0 {
		n, err := strconv.ParseUint(values[0], 10, 16)
		if err != nil || n != 0 {
			return config, fmt.Errorf("only ListenPort = 0 is supported; local ports are allocated automatically")
		}
	}

	if values := fields["Interface.MTU"]; len(values) != 0 {
		n, err := strconv.Atoi(values[0])
		if err != nil || n < 576 || n > 65535 {
			return config, fmt.Errorf("MTU must be between 576 and 65535")
		}

		config.mtu = n
	}

	if config.ipv6 && config.mtu < 1280 {
		return config, fmt.Errorf("IPv6 requires an MTU of at least 1280")
	}

	return config, nil
}

func supportedField(section, key string) bool {
	switch section + "." + key {
	case "Interface.PrivateKey", "Interface.Address", "Interface.DNS",
		"Interface.MTU", "Interface.ListenPort",
		"Peer.PublicKey", "Peer.PresharedKey", "Peer.AllowedIPs",
		"Peer.Endpoint", "Peer.PersistentKeepalive":
		return true
	default:
		return false
	}
}
