package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sampleConfig() string {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))

	return "[Interface]\n" +
		"# Provider comments are ignored.\n" +
		"PrivateKey = " + key + "\n" +
		"Address = 10.2.0.2/32\n" +
		"DNS = 10.2.0.1\n" +
		"[Peer]\n" +
		"PublicKey = " + key + "\n" +
		"AllowedIPs = 0.0.0.0/0, ::/0\n" +
		"Endpoint = 127.0.0.1:51820\n" +
		"PersistentKeepalive = 25\n"
}

func TestConfigIPv4AndIPv6(t *testing.T) {
	config, err := parseConfig(strings.NewReader(sampleConfig()))
	if err != nil {
		t.Fatal(err)
	}

	if config.ipv6 || config.mtu != 1420 || config.keepalive != 25 {
		t.Fatalf("unexpected IPv4 configuration: ipv6=%v mtu=%d keepalive=%d",
			config.ipv6, config.mtu, config.keepalive)
	}

	input := strings.Replace(sampleConfig(),
		"Address = 10.2.0.2/32",
		"Address = 10.2.0.2/32, fd00::2/128", 1)

	config, err = parseConfig(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}

	if !config.ipv6 {
		t.Fatal("IPv6 was not enabled")
	}
}

func TestConfigRejectsUnsupportedOrInvalidInput(t *testing.T) {
	tests := map[string]string{
		"command": strings.Replace(sampleConfig(),
			"DNS = 10.2.0.1", "DNS = 10.2.0.1\nPostUp = touch /tmp/unsafe", 1),
		"second peer": sampleConfig() + "[Peer]\n",
		"bad key": strings.Replace(sampleConfig(),
			"PrivateKey = "+base64.StdEncoding.EncodeToString(make([]byte, 32)),
			"PrivateKey = not-a-key", 1),
		"split tunnel": strings.Replace(sampleConfig(),
			"0.0.0.0/0, ::/0", "10.0.0.0/8", 1),
		"fixed port": strings.Replace(sampleConfig(),
			"DNS = 10.2.0.1", "DNS = 10.2.0.1\nListenPort = 51820", 1),
		"IPv6 DNS without IPv6": strings.Replace(sampleConfig(),
			"DNS = 10.2.0.1", "DNS = fd00::1", 1),
		"missing DNS": strings.Replace(sampleConfig(),
			"DNS = 10.2.0.1\n", "", 1),
		"bad endpoint": strings.Replace(sampleConfig(),
			"127.0.0.1:51820", "127.0.0.1:0", 1),
	}

	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseConfig(strings.NewReader(input)); err == nil {
				t.Fatal("expected a validation error")
			}
		})
	}
}

func TestConfigFilesSortedAndInvalidFileFails(t *testing.T) {
	directory := t.TempDir()

	for _, name := range []string{"z.conf", "a.conf", "ignored.txt"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(sampleConfig()), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	configs, err := loadConfigs(directory)
	if err != nil {
		t.Fatal(err)
	}

	if len(configs) != 2 || configs[0].id != "a" || configs[1].id != "z" {
		t.Fatal("profiles were not sorted or non-.conf files were loaded")
	}

	if err := os.WriteFile(filepath.Join(directory, "broken.conf"), []byte("invalid"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := loadConfigs(directory); err == nil {
		t.Fatal("invalid profile should fail the entire load")
	}
}

func TestAuthorityValidation(t *testing.T) {
	for _, value := range []string{"example.com:443", "[2001:db8::1]:443", "127.0.0.1:80"} {
		if _, _, err := parseAuthority(value); err != nil {
			t.Fatalf("%s: %v", value, err)
		}
	}

	for _, value := range []string{"example.com", ":443", "example.com:0", "example.com:65536", "bad host:80", "[fe80::1%eth0]:80"} {
		if _, _, err := parseAuthority(value); err == nil {
			t.Fatalf("accepted invalid authority %q", value)
		}
	}
}
