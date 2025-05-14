// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/caffix/stringset"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

const (
	outputDirName  = "amass"
	defaultCfgFile = "config.yaml"
	cfgEnvironVar  = "AMASS_CONFIG"
	systemCfgDir   = "/etc"
)

// Updater allows an object to implement a method that updates a configuration.
type Updater interface {
	OverrideConfig(*Config) error
}

// Config passes along Amass configuration settings and options.
type Config struct {
	sync.Mutex `yaml:"-" json:"-"`

	// A Universally Unique Identifier (UUID) for the enumeration
	UUID uuid.UUID `yaml:"-" json:"-"`

	// The pseudo-random number generator
	Rand *rand.Rand `yaml:"-" json:"-"`

	// Logger for error messages
	Log *log.Logger `yaml:"-" json:"-"`

	// The date/time that discoveries must be active since to be included in the findings
	CollectionStartTime time.Time `yaml:"-" json:"-"`

	// Seed struct that contains the provided names and CIDRs
	Seed *Scope `yaml:"seed,omitempty" json:"seed,omitempty"`

	// Scope struct that contains ASN, CIDR, Domain, IP, and ports in scope
	Scope *Scope `yaml:"scope,omitempty" json:"scope,omitempty"`

	// Defines options like datasources config path and stuff like that
	Options map[string]interface{} `yaml:"options,omitempty" json:"-"`

	// The global transformation settings
	DefaultTransformations *Transformation `yaml:"-" json:"-"`

	// Filepath of the configuration file. It is needed as a seed incase of relative paths in the config.
	Filepath string `yaml:"-" json:"-"`

	// Alternative directory for scripts provided by the user
	ScriptsDirectory string `yaml:"-" json:"-"`

	// The directory that stores the bolt db and other files created
	Dir string `yaml:"-" json:"-"`

	// The graph databases used by the system / enumerations
	GraphDBs []*Database `yaml:"-" json:"database,omitempty"`

	// The maximum number of concurrent DNS queries
	MaxDNSQueries int `yaml:"-" json:"-"`

	// The list of words to use when generating names
	Wordlist []string `yaml:"-" json:"wordlist,omitempty"`

	// Will the enumeration including brute forcing techniques
	BruteForcing bool `yaml:"-" json:"brute_force,omitempty"`

	// Will recursive brute forcing be performed?
	Recursive bool `yaml:"-" json:"-"`

	// Minimum number of subdomain discoveries before performing recursive brute forcing
	MinForRecursive int `yaml:"-" json:"-"`

	// Maximum depth for bruteforcing
	MaxDepth int `yaml:"-" json:"-"`

	// Will discovered subdomain name alterations be generated?
	Alterations    bool     `yaml:"-" json:"alterations,omitempty"`
	FlipWords      bool     `yaml:"-" json:"-"`
	FlipNumbers    bool     `yaml:"-" json:"-"`
	AddWords       bool     `yaml:"-" json:"-"`
	AddNumbers     bool     `yaml:"-" json:"-"`
	MinForWordFlip int      `yaml:"-" json:"-"`
	EditDistance   int      `yaml:"-" json:"-"`
	AltWordlist    []string `yaml:"-" json:"alt_worldlist,omitempty"`

	// Only access the data sources for names and return results?
	Passive bool `yaml:"-" json:"-"`

	// Determines if zone transfers will be attempted
	Active bool `yaml:"active,omitempty" json:"active,omitempty"`

	// Determines rigidness of the enumeration
	Rigid bool `yaml:"rigid_boundaries" json:"rigid_boundaries"`

	blacklistLock sync.Mutex `yaml:"-" json:"-"`

	// A list of data sources that should not be utilized
	SourceFilter struct {
		Include bool     `yaml:"-" json:"-"` // true = include, false = exclude
		Sources []string `yaml:"-" json:"-"`
	} `yaml:"-" json:"-"`

	// The minimum number of minutes that data source responses will be reused
	MinimumTTL int `yaml:"-" json:"-"`

	// Type of DNS records to query for
	RecordTypes []string `yaml:"-" json:"-"`

	// Resolver settings
	Resolvers        []string `yaml:"-" json:"resolvers"`
	ResolversQPS     int      `yaml:"-" json:"-"`
	TrustedResolvers []string `yaml:"-" json:"trusted_resolvers,omitempty"`
	TrustedQPS       int      `yaml:"-" json:"-"`

	// Option for verbose logging and output
	Verbose bool `yaml:"-" json:"-"`

	// Names provided to seed the enumeration
	ProvidedNames []string `yaml:"-" json:"-"`

	// The regular expressions for the root domains added to the enumeration
	regexps map[string]*regexp.Regexp `yaml:"-" json:"-"`

	// Mode should be determined based on scripts utilized
	Mode string `yaml:"-" json:"-"`

	// The data source configurations
	DataSrcConfigs *DataSourceConfig `yaml:"-" json:"datasource_config"`

	// The Transformations map will contain incoming assets, and what handlers should be called.
	Transformations map[string]*Transformation `yaml:"transformations" json:"transformations"`

	// The engine APIURI configuration
	EngineAPI *EngAPI `yaml:"-" json:"-"`

	// Map to track 'From' types that have a 'none' transformation, indicating no processing should occur.
	fromWithNone map[string]bool

	// Map to track 'From' types that have at least one valid transformation defined.
	fromWithValid map[string]bool
}

// Scope represents the configuration for the enumeration scope.
type Scope struct {
	// The root domain names that the enumeration will target
	Domains []string `yaml:"domains,omitempty" json:"domains,omitempty"`

	// IP Net.IP
	Addresses []net.IP `yaml:"-" json:"ips,omitempty"`

	// The IP addresses specified as in scope
	IP []string `yaml:"ips,omitempty" json:"-"`

	// ASNs specified as in scope
	ASNs []int `yaml:"asns,omitempty" json:"asns,omitempty"`

	// CIDR IPNET
	CIDRs []*net.IPNet `yaml:"-" json:"cidrs,omitempty"`

	// CIDR in scope
	CIDRStrings []string `yaml:"cidrs,omitempty" json:"-"`

	// Ports as an interface to parse and  for ranges, it is stored as an interface for easy casting
	PortsRaw []interface{} `yaml:"ports,omitempty" json:"-"`

	// The ports checked for certificates
	Ports []int `yaml:"-" json:"ports,omitempty"`

	// A blacklist of subdomain names that will not be investigated
	Blacklist []string `yaml:"blacklist,omitempty" json:"blacklist,omitempty"`
}

// NewConfig returns a default configuration object.
func NewConfig() *Config {
	return &Config{
		UUID:                uuid.New(),
		Rand:                rand.New(rand.NewSource(time.Now().UTC().UnixNano())),
		Log:                 log.New(io.Discard, "", 0),
		CollectionStartTime: time.Now(),
		Seed:                &Scope{},
		Scope:               &Scope{Ports: []int{80, 443}},
		Options:             make(map[string]interface{}),
		MinForRecursive:     1,
		FlipWords:           true,
		FlipNumbers:         true,
		AddWords:            true,
		AddNumbers:          true,
		MinForWordFlip:      2,
		EditDistance:        1,
		Recursive:           true,
		MinimumTTL:          1440,
		ResolversQPS:        DefaultQueriesPerPublicResolver,
		TrustedQPS:          DefaultQueriesPerBaselineResolver,
		DataSrcConfigs: &DataSourceConfig{
			GlobalOptions: make(map[string]int),
		},
		Transformations: make(map[string]*Transformation),
		DefaultTransformations: &Transformation{
			TTL:        1440,
			Confidence: 50,
			Priority:   5,
		},
	}
}

// UpdateConfig allows the provided Updater to update the current configuration.
func (c *Config) UpdateConfig(update Updater) error {
	return update.OverrideConfig(c)
}

// CheckSettings runs some sanity checks on the configuration options selected.
func (c *Config) CheckSettings() error {
	var err error

	if c.BruteForcing {
		if c.Passive {
			return errors.New("brute forcing cannot be performed without DNS resolution")
		}
	}
	if c.Passive && c.Active {
		return errors.New("active enumeration cannot be performed without DNS resolution")
	}

	c.Wordlist, err = ExpandMaskWordlist(c.Wordlist)
	if err != nil {
		return err
	}

	c.AltWordlist, err = ExpandMaskWordlist(c.AltWordlist)
	if err != nil {
		return err
	}
	return err
}

// LoadSettings parses settings from an .yaml file and assigns them to the Config.
func (c *Config) LoadSettings(path string) error {
	// Determine and store the absolute path of the config file
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		_ = c.LoadDatabaseEnvSettings()
		_ = c.LoadEngineEnvSettings()
		return fmt.Errorf("failed to get absolute path of the configuration file: %v", err)
	}
	c.Filepath = absolutePath

	// Open the configuration file
	data, err := os.ReadFile(c.Filepath)
	if err != nil {
		_ = c.LoadDatabaseEnvSettings()
		_ = c.LoadEngineEnvSettings()
		return fmt.Errorf("failed to load the main configuration file: %v", err)
	}

	err = yaml.Unmarshal(data, c)
	if err != nil {
		_ = c.LoadDatabaseEnvSettings()
		_ = c.LoadEngineEnvSettings()
		return fmt.Errorf("error mapping configuration settings to internal values: %v", err)
	}

	if err := c.loadSeedandScopeSettings(); err != nil {
		return err
	}

	loads := []func(cfg *Config) error{
		c.loadAlterationSettings,
		c.loadBruteForceSettings,
		c.loadDatabaseSettings,
		c.loadDataSourceSettings,
		c.loadResolverSettings,
		c.loadTransformSettings,
		c.loadEngineSettings,
		c.loadActiveSettings,
		c.loadRigidSettings,
	}
	for _, load := range loads {
		if err := load(c); err != nil {
			return err
		}
	}

	return nil
}

// AbsPathFromConfigDir Creates a file path that is relative the the configuration file location.
// If the path is already absolute, return it as is.
func (c *Config) AbsPathFromConfigDir(path string) (string, error) {
	// If the path is already absolute, return it as is
	if filepath.IsAbs(path) {
		// Check if the file exists
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return "", fmt.Errorf("file does not exist: %v", err)
		}

		return path, nil
	}
	// Get the directory of the current config file
	cfgDir := filepath.Dir(c.Filepath)
	// Clean the incoming path to ensure it doesn't have any problematic elements
	cleanPath := filepath.Clean(path)
	// Construct the absolute path by joining the config directory and the relative path
	absPath := filepath.Join(cfgDir, cleanPath)
	// Check if the file exists
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		return "", fmt.Errorf("file does not exist: %v", err)
	}
	return absPath, nil
}
func (s *Scope) toCIDRs(strings []string) []*net.IPNet {
	cidrs := make([]*net.IPNet, len(strings))
	for i, str := range strings {
		_, cidr, _ := net.ParseCIDR(str)
		cidrs[i] = cidr
	}
	return cidrs
}

// AcquireConfig populates the Config struct provided by the Config argument.
func AcquireConfig(dir, file string, cfg *Config) error {
	var path, dircfg, syscfg string

	cfg.Dir = OutputDirectory(dir)
	if finfo, err := os.Stat(cfg.Dir); cfg.Dir != "" && !os.IsNotExist(err) && finfo.IsDir() {
		dircfg = filepath.Join(cfg.Dir, defaultCfgFile)
	}

	if runtime.GOOS != "windows" {
		syscfg = filepath.Join(filepath.Join(systemCfgDir, outputDirName), defaultCfgFile)
	}

	if file != "" {
		path = file
	} else if f, set := os.LookupEnv(cfgEnvironVar); set {
		path = f
	} else if _, err := os.Stat(dircfg); err == nil {
		path = dircfg
	} else if _, err := os.Stat(syscfg); err == nil {
		path = syscfg
	}

	return cfg.LoadSettings(path)
}

// OutputDirectory returns the file path of the Amass output directory. A suitable
// path provided will be used as the output directory instead.
func OutputDirectory(dir ...string) string {
	if len(dir) > 0 && dir[0] != "" {
		return dir[0]
	}

	if path, err := os.UserConfigDir(); err == nil {
		return filepath.Join(path, outputDirName)
	}

	return ""
}

// GetListFromFile reads a wordlist text or gzip file and returns the slice of words.
func GetListFromFile(path string) ([]string, error) {
	var reader io.Reader

	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %v", err)
	}

	file, err := os.Open(absPath)
	if err != nil {
		return nil, fmt.Errorf("error opening the file %s: %v", absPath, err)
	}
	defer func() { _ = file.Close() }()
	reader = file

	// We need to determine if this is a gzipped file or a plain text file, so we
	// first read the first 512 bytes to pass them down to http.DetectContentType
	// for mime detection. The file is rewinded before passing it along to the
	// next reader
	head := make([]byte, 512)
	if _, err = file.Read(head); err != nil {
		return nil, fmt.Errorf("error reading the first 512 bytes from %s: %s", absPath, err)
	}
	if _, err = file.Seek(0, 0); err != nil {
		return nil, fmt.Errorf("error rewinding the file %s: %s", absPath, err)
	}

	// Read the file as gzip if it's actually compressed
	if mt := http.DetectContentType(head); mt == "application/gzip" || mt == "application/x-gzip" {
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			return nil, fmt.Errorf("error gz-reading the file %s: %v", absPath, err)
		}
		defer func() { _ = gzReader.Close() }()
		reader = gzReader
	}

	s, err := getWordList(reader)
	return s, err
}

func getWordList(reader io.Reader) ([]string, error) {
	var words []string

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		// Get the next word in the list
		w := strings.TrimSpace(scanner.Text())
		if err := scanner.Err(); err == nil && w != "" {
			words = append(words, w)
		}
	}
	return stringset.Deduplicate(words), nil
}

// JSON returns the JSON encoding of the configuration without escaping HTML characters.
func (c *Config) JSON() ([]byte, error) {
	type Alias Config
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)

	err := encoder.Encode(&struct{ *Alias }{Alias: (*Alias)(c)})
	if err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}
