// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// In-depth Attack Surface Mapping and Asset Discovery
//
//	+----------------------------------------------------------------------------+
//	| ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  OWASP Amass  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ |
//	+----------------------------------------------------------------------------+
//	|      .+++:.            :                             .+++.                 |
//	|    +W@@@@@@8        &+W@#               o8W8:      +W@@@@@@#.   oW@@@W#+   |
//	|   &@#+   .o@##.    .@@@o@W.o@@o       :@@#&W8o    .@#:  .:oW+  .@#+++&#&   |
//	|  +@&        &@&     #@8 +@W@&8@+     :@W.   +@8   +@:          .@8         |
//	|  8@          @@     8@o  8@8  WW    .@W      W@+  .@W.          o@#:       |
//	|  WW          &@o    &@:  o@+  o@+   #@.      8@o   +W@#+.        +W@8:     |
//	|  #@          :@W    &@+  &@+   @8  :@o       o@o     oW@@W+        oW@8    |
//	|  o@+          @@&   &@+  &@+   #@  &@.      .W@W       .+#@&         o@W.  |
//	|   WW         +@W@8. &@+  :&    o@+ #@      :@W&@&         &@:  ..     :@o  |
//	|   :@W:      o@# +Wo &@+        :W: +@W&o++o@W. &@&  8@#o+&@W.  #@:    o@+  |
//	|    :W@@WWWW@@8       +              :&W@@@@&    &W  .o#@@W&.   :W@WWW@@&   |
//	|      +o&&&&+.                                                    +oooo.    |
//	+----------------------------------------------------------------------------+
package main

import (
	"bufio"
	"bytes"
	"embed"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/caffix/stringset"
	"github.com/fatih/color"
	"github.com/glebarez/sqlite"
	"github.com/owasp-amass/amass/v4/format"
	assetdb "github.com/owasp-amass/asset-db"
	db "github.com/owasp-amass/asset-db"
	pgmigrations "github.com/owasp-amass/asset-db/migrations/postgres"
	sqlitemigrations "github.com/owasp-amass/asset-db/migrations/sqlite3"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/config/config"
	et "github.com/owasp-amass/engine/types"
	"github.com/owasp-amass/open-asset-model/domain"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	migrate "github.com/rubenv/sql-migrate"
	slogcommon "github.com/samber/slog-common"
	slogsyslog "github.com/samber/slog-syslog/v2"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

const (
	mainUsageMsg         = "intel|enum [options]"
	exampleConfigFileURL = "https://github.com/owasp-amass/amass/blob/master/examples/config.yaml"
	userGuideURL         = "https://github.com/owasp-amass/amass/blob/master/doc/user_guide.md"
	tutorialURL          = "https://github.com/owasp-amass/amass/blob/master/doc/tutorial.md"
)

var (
	// Colors used to ease the reading of program output
	b = color.New(color.FgHiBlue)
	//y       = color.New(color.FgHiYellow)
	g = color.New(color.FgHiGreen)
	r = color.New(color.FgHiRed)
	//fgR    = color.New(color.FgRed)
	//fgY    = color.New(color.FgYellow)
	yellow = color.New(color.FgHiYellow).SprintFunc()
	green  = color.New(color.FgHiGreen).SprintFunc()
	blue   = color.New(color.FgHiBlue).SprintFunc()
	//magenta = color.New(color.FgHiMagenta).SprintFunc()
	//white   = color.New(color.FgHiWhite).SprintFunc()
)

func commandUsage(msg string, cmdFlagSet *flag.FlagSet, errBuf *bytes.Buffer) {
	format.PrintBanner()
	g.Fprintf(color.Error, "Usage: %s %s\n\n", path.Base(os.Args[0]), msg)
	cmdFlagSet.PrintDefaults()
	g.Fprintln(color.Error, errBuf.String())

	if msg == mainUsageMsg {
		g.Fprintf(color.Error, "\nSubcommands: \n\n")
		g.Fprintf(color.Error, "\t%-11s - Discover targets for enumerations\n", "amass intel")
		g.Fprintf(color.Error, "\t%-11s - Perform enumerations and network mapping\n", "amass enum")
		g.Fprintf(color.Error, "\t%-11s - Analyze subdomain information in the asset-db\n", "amass subs")
		g.Fprintf(color.Error, "\t%-11s - Analyze OAM data to generate graph visualizations\n", "amass viz")
		g.Fprintf(color.Error, "\t%-11s - Analyze OAM data to identify newly discovered assets\n", "amass track")
	}

	g.Fprintln(color.Error)
	g.Fprintf(color.Error, "The user's guide can be found here: \n%s\n\n", userGuideURL)
	g.Fprintf(color.Error, "An example configuration file can be found here: \n%s\n\n", exampleConfigFileURL)
	g.Fprintf(color.Error, "The Amass tutorial can be found here: \n%s\n\n", tutorialURL)
}

func main() {
	var version, help1, help2 bool
	mainFlagSet := flag.NewFlagSet("amass", flag.ContinueOnError)

	defaultBuf := new(bytes.Buffer)
	mainFlagSet.SetOutput(defaultBuf)

	mainFlagSet.BoolVar(&help1, "h", false, "Show the program usage message")
	mainFlagSet.BoolVar(&help2, "help", false, "Show the program usage message")
	mainFlagSet.BoolVar(&version, "version", false, "Print the version number of this Amass binary")

	if len(os.Args) < 2 {
		commandUsage(mainUsageMsg, mainFlagSet, defaultBuf)
		return
	}
	if err := mainFlagSet.Parse(os.Args[1:]); err != nil {
		r.Fprintf(color.Error, "%v\n", err)
		os.Exit(1)
	}
	if help1 || help2 {
		commandUsage(mainUsageMsg, mainFlagSet, defaultBuf)
		return
	}
	if version {
		fmt.Fprintf(color.Error, "%s\n", format.Version)
		return
	}

	switch os.Args[1] {
	case "enum":
		runEnumCommand(os.Args[2:])
	case "subs":
		runSubsCommand(os.Args[2:])
	case "emails":
		runEmailsCommand(os.Args[2:])
	case "viz":
		runVizCommand(os.Args[2:])
	case "track":
		runTrackCommand(os.Args[2:])
	case "help":
		runHelpCommand(os.Args[2:])
	default:
		commandUsage(mainUsageMsg, mainFlagSet, defaultBuf)
		os.Exit(1)
	}
}

func createOutputDirectory(cfg *config.Config) {
	// Prepare output file paths
	dir := config.OutputDirectory(cfg.Dir)
	if dir == "" {
		r.Fprintln(color.Error, "Failed to obtain the output directory")
		os.Exit(1)
	}
	// If the directory does not yet exist, create it
	if err := os.MkdirAll(dir, 0755); err != nil {
		r.Fprintf(color.Error, "Failed to create the directory: %v\n", err)
		os.Exit(1)
	}
}

func openGraphDatabase(cfg *config.Config) *assetdb.AssetDB {
	// Add the local database settings to the configuration
	cfg.GraphDBs = append(cfg.GraphDBs, cfg.LocalDatabaseSettings(cfg.GraphDBs))

	for _, db := range cfg.GraphDBs {
		if db.Primary {
			var dbase *assetdb.AssetDB

			if db.System == "local" {
				dbase = NewGraph(db.System, filepath.Join(config.OutputDirectory(cfg.Dir), "amass.sqlite"), db.Options)
			} else {
				connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s", db.Host, db.Port, db.Username, db.Password, db.DBName)
				dbase = NewGraph(db.System, connStr, db.Options)
			}

			if dbase != nil {
				return dbase
			}
			break
		}
	}

	return NewGraph("memory", "", "")
}

func NewGraph(system, path string, options string) *assetdb.AssetDB {
	var dsn string
	var dbtype repository.DBType

	switch system {
	case "memory":
		dbtype = repository.SQLite
		dsn = fmt.Sprintf("file:sqlite%d?mode=memory&cache=shared", rand.Int31n(100))
	case "local":
		dbtype = repository.SQLite
		dsn = path
	case "postgres":
		dbtype = repository.Postgres
		dsn = path
	default:
		return nil
	}

	store := db.New(dbtype, dsn)
	if store == nil {
		return nil
	}

	var name string
	var fs embed.FS
	var database gorm.Dialector
	switch dbtype {
	case repository.SQLite:
		name = "sqlite3"
		fs = sqlitemigrations.Migrations()
		database = sqlite.Open(dsn)
	case repository.Postgres:
		name = "postgres"
		fs = pgmigrations.Migrations()
		database = postgres.Open(dsn)
	}

	sql, err := gorm.Open(database, &gorm.Config{})
	if err != nil {
		return nil
	}

	migrationsSource := migrate.EmbedFileSystemMigrationSource{
		FileSystem: fs,
		Root:       "/",
	}

	sqlDb, err := sql.DB()
	if err != nil {
		panic(err)
	}

	_, err = migrate.Exec(sqlDb, name, migrationsSource, migrate.Up)
	if err != nil {
		panic(err)
	}
	return store
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

// returns Asset objects by converting the contests of config.Scope
func makeAssets(config *config.Config) []*et.Asset {
	assets := convertScopeToAssets(config.Scope)

	for i, asset := range assets {
		asset.Name = fmt.Sprintf("asset#%d", i+1)
	}

	return assets
}

// ipnet2Prefix converts a net.IPNet to a netip.Prefix.
func ipnet2Prefix(ipn net.IPNet) netip.Prefix {
	addr, _ := netip.AddrFromSlice(ipn.IP)
	cidr, _ := ipn.Mask.Size()
	return netip.PrefixFrom(addr, cidr)
}

// convertScopeToAssets converts all items in a Scope to a slice of *Asset.
func convertScopeToAssets(scope *config.Scope) []*et.Asset {
	const ipv4 = "IPv4"
	const ipv6 = "IPv6"
	var assets []*et.Asset

	// Convert Domains to assets.
	for _, d := range scope.Domains {
		fqdn := domain.FQDN{Name: d}
		data := et.AssetData{
			OAMAsset: fqdn,
			OAMType:  fqdn.AssetType(),
		}
		asset := &et.Asset{
			Data: data,
		}
		assets = append(assets, asset)
	}

	var ipType string
	// Convert Addresses to assets.
	for _, ip := range scope.Addresses {
		// Convert net.IP to net.IPAddr.
		if addr, ok := netip.AddrFromSlice(ip); ok {
			// Determine the IP type based on the address characteristics.
			if addr.Is4In6() {
				addr = netip.AddrFrom4(addr.As4())
				ipType = ipv4
			} else if addr.Is6() {
				ipType = ipv6
			} else {
				ipType = ipv4
			}

			// Create an asset from the IP address and append it to the assets slice.
			asset := oamnet.IPAddress{Address: addr, Type: ipType}
			data := et.AssetData{
				OAMAsset: asset,
				OAMType:  asset.AssetType(),
			}
			assets = append(assets, &et.Asset{Data: data})
		}
	}

	// Convert CIDRs to assets.
	for _, cidr := range scope.CIDRs {
		prefix := ipnet2Prefix(*cidr) // Convert net.IPNet to netip.Prefix.

		// Determine the IP type based on the address characteristics.
		addr := prefix.Addr()
		if addr.Is4In6() {
			ipType = ipv4
		} else if addr.Is6() {
			ipType = ipv6
		} else {
			ipType = ipv4
		}

		// Create an asset from the CIDR and append it to the assets slice.
		asset := oamnet.Netblock{Cidr: prefix, Type: ipType}
		data := et.AssetData{
			OAMAsset: asset,
			OAMType:  asset.AssetType(),
		}
		assets = append(assets, &et.Asset{Data: data})
	}

	// Convert ASNs to assets.
	for _, asn := range scope.ASNs {
		asset := oamnet.AutonomousSystem{Number: asn}
		data := et.AssetData{
			OAMAsset: asset,
			OAMType:  asset.AssetType(),
		}
		assets = append(assets, &et.Asset{Data: data})
	}

	return assets
}

func selectLogger(dir, logfile string) *slog.Logger {
	if logfile == "" {
		if l := setupSyslogLogger(); l != nil {
			return l
		}
	}
	return setupFileLogger(dir, logfile)
}

func setupFileLogger(dir, logfile string) *slog.Logger {
	if dir != "" {
		if err := os.MkdirAll(dir, 0640); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create the log directory: %v", err)
		}
	}

	p := filepath.Join(dir, fmt.Sprintf("amass_client_%s.log", time.Now().Format("2006-01-02T15:04:05")))
	if logfile != "" {
		p = logfile
	}

	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open the log file: %v", err)
		return nil
	}

	return slog.New(slog.NewJSONHandler(f, nil))
}

func setupSyslogLogger() *slog.Logger {
	port := os.Getenv("SYSLOG_PORT")
	host := strings.ToLower(os.Getenv("SYSLOG_HOST"))
	transport := strings.ToLower(os.Getenv("SYSLOG_TRANSPORT"))

	if host == "" {
		return nil
	}
	if port == "" {
		port = "514"
	}
	if transport == "" {
		transport = "udp"
	}

	writer, err := net.Dial(transport, net.JoinHostPort(host, port))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create the connection to the log server: %v", err)
		return nil
	}

	return slog.New(slogsyslog.Option{
		Level:     slog.LevelInfo,
		Converter: syslogConverter,
		Writer:    writer,
	}.NewSyslogHandler())
}

func syslogConverter(addSource bool, replaceAttr func(groups []string, a slog.Attr) slog.Attr, loggerAttr []slog.Attr, groups []string, record *slog.Record) map[string]any {
	attrs := slogcommon.AppendRecordAttrsToAttrs(loggerAttr, groups, record)
	attrs = slogcommon.ReplaceAttrs(replaceAttr, []string{}, attrs...)

	return map[string]any{
		"level":   record.Level.String(),
		"message": record.Message,
		"attrs":   slogcommon.AttrsToMap(attrs...),
	}
}
