// Copyright © by Jeff Foley 2017-2025. All rights reserved.
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
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/caffix/stringset"
	"github.com/fatih/color"
	"github.com/owasp-amass/amass/v4/config"
	et "github.com/owasp-amass/amass/v4/engine/types"
	"github.com/owasp-amass/amass/v4/utils/afmt"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	slogcommon "github.com/samber/slog-common"
	slogsyslog "github.com/samber/slog-syslog/v2"
)

const (
	mainUsageMsg      = "enum [options]"
	documentationURL  = "https://owasp-amass.github.io/docs"
	discordInvitation = "https://discord.gg/ANTyEDUXt5"
	youTubeURL        = "https://www.youtube.com/@jeff_foley"
)

func main() {
	runEnumCommand(os.Args[1:])
}

func commandUsage(msg string, cmdFlagSet *flag.FlagSet, errBuf *bytes.Buffer) {
	afmt.PrintBanner()
	_, _ = afmt.G.Fprintf(color.Error, "Usage: %s %s\n\n", path.Base(os.Args[0]), msg)
	cmdFlagSet.PrintDefaults()
	_, _ = afmt.G.Fprintln(color.Error, errBuf.String())

	if msg == mainUsageMsg {
		_, _ = afmt.G.Fprintf(color.Error, "\nSubcommands: \n\n")
		_, _ = afmt.G.Fprintf(color.Error, "\t%-11s - Perform enumerations and network mapping\n", "amass enum")
	}

	_, _ = afmt.G.Fprintln(color.Error)
	_, _ = afmt.G.Fprintf(color.Error, "The project documentation can be found here: \n%s\n\n", documentationURL)
	_, _ = afmt.G.Fprintf(color.Error, "The Amass Discord server can be found here: \n%s\n\n", discordInvitation)
	_, _ = afmt.G.Fprintf(color.Error, "The Amass YouTube channel can be found here: \n%s\n\n", youTubeURL)
}

func createOutputDirectory(cfg *config.Config) {
	// Prepare output file paths
	dir := config.OutputDirectory(cfg.Dir)
	if dir == "" {
		_, _ = afmt.R.Fprintln(color.Error, "Failed to obtain the output directory")
		os.Exit(1)
	}
	// If the directory does not yet exist, create it
	if err := os.MkdirAll(dir, 0755); err != nil {
		_, _ = afmt.R.Fprintf(color.Error, "Failed to create the directory: %v\n", err)
		os.Exit(1)
	}
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
		fqdn := oamdns.FQDN{Name: d}
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
		asset := oamnet.Netblock{CIDR: prefix, Type: ipType}
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
			_, _ = fmt.Fprintf(os.Stderr, "Failed to create the log directory: %v", err)
		}
	}

	p := filepath.Join(dir, fmt.Sprintf("amass_client_%s.log", time.Now().Format("2006-01-02T15:04:05")))
	if logfile != "" {
		p = logfile
	}

	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to open the log file: %v", err)
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
		_, _ = fmt.Fprintf(os.Stderr, "Failed to create the connection to the log server: %v", err)
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
