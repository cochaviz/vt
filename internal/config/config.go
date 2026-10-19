// Package config loads and saves the vt client settings file.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

// Config holds the persisted client settings.
type Config struct {
	APIKey         string `yaml:"api_key,omitempty"`
	DownloadDir    string `yaml:"download_dir,omitempty"`
	ZipPassword    string `yaml:"zip_password,omitempty"`
	PollInterval   string `yaml:"poll_interval,omitempty"`
	RequestTimeout string `yaml:"request_timeout,omitempty"`
}

// Key describes one settable config key.
type Key struct {
	Name   string
	Help   string
	Secret bool
	field  func(*Config) *string
}

var keys = []Key{
	{Name: "api_key", Help: "VirusTotal API key (also VT_API_KEY)", Secret: true, field: func(c *Config) *string { return &c.APIKey }},
	{Name: "download_dir", Help: "default output directory for downloads", field: func(c *Config) *string { return &c.DownloadDir }},
	{Name: "zip_password", Help: "password for downloaded zips (default \"infected\")", field: func(c *Config) *string { return &c.ZipPassword }},
	{Name: "poll_interval", Help: "how often to poll analyses/zips, e.g. 15s", field: func(c *Config) *string { return &c.PollInterval }},
	{Name: "request_timeout", Help: "HTTP timeout per request, e.g. 2m (0 = none)", field: func(c *Config) *string { return &c.RequestTimeout }},
}

// Keys returns all settable keys, sorted by name.
func Keys() []Key {
	out := append([]Key(nil), keys...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func lookup(name string) (Key, error) {
	for _, k := range keys {
		if k.Name == name {
			return k, nil
		}
	}
	return Key{}, fmt.Errorf("unknown config key %q", name)
}

// Get returns the value of a key.
func (c *Config) Get(name string) (string, error) {
	k, err := lookup(name)
	if err != nil {
		return "", err
	}
	return *k.field(c), nil
}

// Set assigns a key. An empty value clears it.
func (c *Config) Set(name, value string) error {
	k, err := lookup(name)
	if err != nil {
		return err
	}
	*k.field(c) = value
	return nil
}

// Path returns the config file location, honoring VT_CONFIG.
func Path() string {
	if p := os.Getenv("VT_CONFIG"); p != "" {
		return p
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = "."
	}
	return filepath.Join(dir, "vt", "vt.yaml")
}

// Load reads the config file. A missing file yields an empty config.
func Load() (*Config, error) {
	c := &Config{}
	b, err := os.ReadFile(Path())
	if errors.Is(err, fs.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", Path(), err)
	}
	return c, nil
}

// Save writes the config file with owner-only permissions, since it holds the API key.
func (c *Config) Save() error {
	p := Path()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o600)
}
