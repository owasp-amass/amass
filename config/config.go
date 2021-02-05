// Copyright 2017-2020 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package config

import (
	"bufio"
	"compress/gzip"
	"context"
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
	"strconv"
	"strings"
	"sync"

	_ "github.com/OWASP/Amass/v3/config/statik" // The content being embedded into the binary
	amasshttp "github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/wordlist"
	"github.com/caffix/stringset"
	"github.com/go-ini/ini"
	"github.com/google/uuid"
	"github.com/rakyll/statik/fs"
)

const (
	outputDirectoryName = "amass"
)

var (
	// StatikFS is the ./resources project directory embedded into the binary.
	StatikFS http.FileSystem
	fsOnce   sync.Once
)

func openTheFS() {
	StatikFS, _ = fs.New()
}

// Updater allows an object to implement a method that updates a configuration.
type Updater interface {
	OverrideConfig(*Config) error
}

type Logger interface {
	Printf(format string, v ...interface{})
	Print(v ...interface{})
	Println(v ...interface{})
}

// Config passes along Amass configuration settings and options.
type Config struct {
	sync.Mutex

	// A Universally Unique Identifier (UUID) for the enumeration
	UUID uuid.UUID

	// Logger for error messages
	Log Logger

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
	Blacklist []string

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
	Resolvers           []string
	MonitorResolverRate bool

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
		UUID:                uuid.New(),
		Log:                 log.New(ioutil.Discard, "", 0),
		Ports:               []int{443},
		MinForRecursive:     1,
		MonitorResolverRate: true,
		LocalDatabase:       true,
		// The following is enum-only, but intel will just ignore them anyway
		Alterations:    true,
		FlipWords:      true,
		FlipNumbers:    true,
		AddWords:       true,
		AddNumbers:     true,
		MinForWordFlip: 2,
		EditDistance:   1,
		Recursive:      true,
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
			return errors.New("Brute forcing cannot be performed without DNS resolution")
		} else if len(c.Wordlist) == 0 {
			c.Wordlist, err = getWordlistByFS("/namelist.txt")
			if err != nil {
				return err
			}
		}
	}
	if c.Passive && c.Active {
		return errors.New("Active enumeration cannot be performed without DNS resolution")
	}
	if c.Alterations {
		if len(c.AltWordlist) == 0 {
			c.AltWordlist, err = getWordlistByFS("/alterations.txt")
			if err != nil {
				return err
			}
		}
	}

	c.Wordlist, err = wordlist.ExpandMaskWordlist(c.Wordlist)
	if err != nil {
		return err
	}

	c.AltWordlist, err = wordlist.ExpandMaskWordlist(c.AltWordlist)
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
		return fmt.Errorf("Failed to load the configuration file: %v", err)
	}
	// Get the easy ones out of the way using mapping
	if err = cfg.MapTo(c); err != nil {
		return fmt.Errorf("Error mapping configuration settings to internal values: %v", err)
	}
	// Attempt to load a special mode of operation specified by the user
	if cfg.Section(ini.DEFAULT_SECTION).HasKey("mode") {
		mode := cfg.Section(ini.DEFAULT_SECTION).Key("mode").String()

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

// AcquireConfig populates the Config struct provided by the config argument.
func AcquireConfig(dir, file string, config *Config) error {
	var err error

	if file != "" {
		err = config.LoadSettings(file)
		if err == nil {
			return nil
		}
	}
	// Attempt to obtain the configuration file from the output directory
	if dir = OutputDirectory(dir); dir != "" {
		if finfo, err := os.Stat(dir); !os.IsNotExist(err) && finfo.IsDir() {
			file := filepath.Join(dir, "config.ini")

			err = config.LoadSettings(file)
			if err == nil {
				return nil
			}
		}
	}
	return err
}

// OutputDirectory returns the file path of the Amass output directory. A suitable
// path provided will be used as the output directory instead.
func OutputDirectory(dir ...string) string {
	if len(dir) > 0 && dir[0] != "" {
		return dir[0]
	}

	if path, err := os.UserConfigDir(); err == nil {
		return filepath.Join(path, outputDirectoryName)
	}

	return ""
}

// GetListFromFile reads a wordlist text or gzip file and returns the slice of words.
func GetListFromFile(path string) ([]string, error) {
	var reader io.Reader

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("Error opening the file %s: %v", path, err)
	}
	defer file.Close()
	reader = file

	// We need to determine if this is a gzipped file or a plain text file, so we
	// first read the first 512 bytes to pass them down to http.DetectContentType
	// for mime detection. The file is rewinded before passing it along to the
	// next reader
	head := make([]byte, 512)
	if _, err = file.Read(head); err != nil {
		return nil, fmt.Errorf("Error reading the first 512 bytes from %s: %s", path, err)
	}
	if _, err = file.Seek(0, 0); err != nil {
		return nil, fmt.Errorf("Error rewinding the file %s: %s", path, err)
	}

	// Read the file as gzip if it's actually compressed
	if mt := http.DetectContentType(head); mt == "application/gzip" || mt == "application/x-gzip" {
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			return nil, fmt.Errorf("Error gz-reading the file %s: %v", path, err)
		}
		defer gzReader.Close()
		reader = gzReader
	}

	s, err := getWordList(reader)
	return s, err
}

func getWordlistByURL(ctx context.Context, url string) ([]string, error) {
	page, err := amasshttp.RequestWebPage(ctx, url, nil, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("Failed to obtain the wordlist at %s: %v", url, err)
	}
	return getWordList(strings.NewReader(page))
}

func getWordlistByFS(path string) ([]string, error) {
	fsOnce.Do(openTheFS)

	content, err := StatikFS.Open(path)
	if err != nil {
		return nil, fmt.Errorf("Failed to obtain the embedded wordlist: %s: %v", path, err)
	}
	return getWordList(content)
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
