// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package config

import (
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/OWASP/Amass/v3/resources"
	"github.com/caffix/stringset"
	"github.com/go-ini/ini"
	"github.com/google/uuid"
)

const (
	outputDirName  = "amass"
	defaultCfgFile = "config.ini"
	cfgEnvironVar  = "AMASS_CONFIG"
	systemCfgDir   = "/etc"
)

// Updater allows an object to implement a method that updates a configuration.
type Updater interface {
	OverrideConfig(*Config) error
}

// Config passes along Amass configuration settings and options.
type Config struct {
	sync.Mutex

	// A Universally Unique Identifier (UUID) for the enumeration
	UUID uuid.UUID

	// Logger for error messages
	Log *log.Logger

	// Share activates the process that shares findings with providers for service credits
	Share bool `ini:"share"`

	// The directory that stores the bolt db and other files created
	Dir string `ini:"output_directory"`

	// Alternative directory for scripts provided by the user
	ScriptsDirectory string `ini:"scripts_directory"`

	// Use a local graph database
	LocalDatabase bool

	// The graph databases used by the system / enumerations
	GraphDBs []*Database

	// The maximum number of concurrent DNS queries
	MaxDNSQueries int `ini:"maximum_dns_queries"`

	// Names provided to seed the enumeration
	ProvidedNames []string

	// The IP addresses specified as in scope
	Addresses []net.IP

	// CIDR that is in scope
	CIDRs []*net.IPNet

	// ASNs specified as in scope
	ASNs []int

	// The ports that will be checked for certificates
	Ports []int

	// The list of words to use when generating names
	Wordlist []string

	// Will the enumeration including brute forcing techniques
	BruteForcing bool

	// Will recursive brute forcing be performed?
	Recursive bool

	// Minimum number of subdomain discoveries before performing recursive brute forcing
	MinForRecursive int

	// Will discovered subdomain name alterations be generated?
	Alterations    bool
	FlipWords      bool
	FlipNumbers    bool
	AddWords       bool
	AddNumbers     bool
	MinForWordFlip int
	EditDistance   int
	AltWordlist    []string

	// Only access the data sources for names and return results?
	Passive bool

	// Determines if zone transfers will be attempted
	Active bool

	// A blacklist of subdomain names that will not be investigated
	Blacklist     []string
	blacklistLock sync.Mutex

	// A list of data sources that should not be utilized
	SourceFilter struct {
		Include bool // true = include, false = exclude
		Sources []string
	}

	// The minimum number of minutes that data source responses will be reused
	MinimumTTL int

	// Type of DNS records to query for
	RecordTypes []string

	// Resolver settings
	Resolvers []string

	// Option for verbose logging and output
	Verbose bool

	// The root domain names that the enumeration will target
	domains []string

	// The regular expressions for the root domains added to the enumeration
	regexps map[string]*regexp.Regexp

	// The data source configurations
	datasrcConfigs map[string]*DataSourceConfig
}

// NewConfig returns a default configuration object.
func NewConfig() *Config {
	c := &Config{
		UUID:            uuid.New(),
		Log:             log.New(ioutil.Discard, "", 0),
		Ports:           []int{80, 443},
		MinForRecursive: 1,
		LocalDatabase:   true,
		// The following is enum-only, but intel will just ignore them anyway
		Alterations:    true,
		FlipWords:      true,
		FlipNumbers:    true,
		AddWords:       true,
		AddNumbers:     true,
		MinForWordFlip: 2,
		EditDistance:   1,
		Recursive:      true,
		MinimumTTL:     1440,
	}

	c.calcDNSQueriesMax()
	return c
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
		} else if len(c.Wordlist) == 0 {
			f, err := resources.GetResourceFile("namelist.txt")
			if err != nil {
				return err
			}

			c.Wordlist, err = getWordList(f)
			if err != nil {
				return err
			}
		}
	}
	if c.Passive && c.Active {
		return errors.New("active enumeration cannot be performed without DNS resolution")
	}
	if c.Alterations {
		if len(c.AltWordlist) == 0 {
			f, err := resources.GetResourceFile("alterations.txt")
			if err != nil {
				return err
			}

			c.AltWordlist, err = getWordList(f)
			if err != nil {
				return err
			}
		}
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

// LoadSettings parses settings from an .ini file and assigns them to the Config.
func (c *Config) LoadSettings(path string) error {
	cfg, err := ini.LoadSources(ini.LoadOptions{
		Insensitive:  true,
		AllowShadows: true,
	}, path)
	if err != nil {
		return fmt.Errorf("failed to load the configuration file: %v", err)
	}
	// Get the easy ones out of the way using mapping
	if err = cfg.MapTo(c); err != nil {
		return fmt.Errorf("error mapping configuration settings to internal values: %v", err)
	}
	// Attempt to load a special mode of operation specified by the user
	if cfg.Section(ini.DefaultSection).HasKey("mode") {
		mode := cfg.Section(ini.DefaultSection).Key("mode").String()

		if mode == "passive" {
			c.Passive = true
		} else if mode == "active" {
			c.Active = true
		}
	}

	loads := []func(cfg *ini.File) error{
		c.loadResolverSettings,
		c.loadScopeSettings,
		c.loadAlterationSettings,
		c.loadBruteForceSettings,
		c.loadDatabaseSettings,
		c.loadDataSourceSettings,
	}
	for _, load := range loads {
		if err := load(cfg); err != nil {
			return err
		}
	}

	return nil
}

// AcquireConfig populates the Config struct provided by the Config argument.
func AcquireConfig(dir, file string, cfg *Config) error {
	var path, dircfg, syscfg string

	d := OutputDirectory(dir)
	if finfo, err := os.Stat(d); d != "" && !os.IsNotExist(err) && finfo.IsDir() {
		dircfg = filepath.Join(d, defaultCfgFile)
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

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error opening the file %s: %v", path, err)
	}
	defer file.Close()
	reader = file

	// We need to determine if this is a gzipped file or a plain text file, so we
	// first read the first 512 bytes to pass them down to http.DetectContentType
	// for mime detection. The file is rewinded before passing it along to the
	// next reader
	head := make([]byte, 512)
	if _, err = file.Read(head); err != nil {
		return nil, fmt.Errorf("error reading the first 512 bytes from %s: %s", path, err)
	}
	if _, err = file.Seek(0, 0); err != nil {
		return nil, fmt.Errorf("error rewinding the file %s: %s", path, err)
	}

	// Read the file as gzip if it's actually compressed
	if mt := http.DetectContentType(head); mt == "application/gzip" || mt == "application/x-gzip" {
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			return nil, fmt.Errorf("error gz-reading the file %s: %v", path, err)
		}
		defer gzReader.Close()
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

func uniqueIntAppend(s []int, e string) []int {
	if a1, err := strconv.Atoi(e); err == nil {
		var found bool

		for _, a2 := range s {
			if a1 == a2 {
				found = true
				break
			}
		}
		if !found {
			s = append(s, a1)
		}
	}
	return s
}
