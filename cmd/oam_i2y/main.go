// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// oam_i2y: Converts legacy INI configuration to YAML!
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
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"

	"github.com/fatih/color"
	"github.com/owasp-amass/config/config"
	"gopkg.in/yaml.v3"
)

const (
	usageMsg = "[options]"
)

var (
	g = color.New(color.FgHiGreen)
	r = color.New(color.FgHiRed)
	b = color.New(color.FgHiBlue)
	p = color.New(color.FgHiMagenta)
)

func main() {
	var help1, help2 bool
	var iniFile, configFile, datasrcFile string
	var err error
	i2yCommand := flag.NewFlagSet("db", flag.ContinueOnError)

	i2yBuf := new(bytes.Buffer)
	i2yCommand.SetOutput(i2yBuf)

	i2yCommand.BoolVar(&help1, "h", false, "Show the program usage message")
	i2yCommand.BoolVar(&help2, "help", false, "Show the program usage message")
	i2yCommand.StringVar(&iniFile, "ini", "", "Path to the INI configuration file.")
	i2yCommand.StringVar(&configFile, "cf", "oam_config.yaml", "YAML configuration file name.")
	i2yCommand.StringVar(&datasrcFile, "df", "oam_datasources.yaml", "YAML data sources file name.")

	var usage = func() {
		g.Fprintf(color.Error, "Usage: %s %s\n\n", path.Base(os.Args[0]), usageMsg)
		i2yCommand.PrintDefaults()
		g.Fprintln(color.Error, i2yBuf.String())
	}

	if len(os.Args) < 2 {
		usage()
		return
	}
	if err := i2yCommand.Parse(os.Args[1:]); err != nil {
		r.Fprintf(color.Error, "%v\n", err)
		os.Exit(1)
	}
	if help1 || help2 {
		usage()
		return
	}
	if iniFile == "" {
		usage()
		r.Fprintln(color.Error, "Failed to parse the INI file: File not present, got \""+iniFile+"\" as the path.")
		return
	}

	// converts the file paths to absolute paths
	configFile, err = filepath.Abs(configFile)
	if err != nil {
		log.Fatal("Failed to get the absolute config path:", err)
	}
	datasrcFile, err = filepath.Abs(datasrcFile)
	if err != nil {
		log.Fatal("Failed to get the absolute data source path:", err)
	}

	iniConfig := Config{}
	if err := iniConfig.LoadSettings(iniFile); err != nil {
		log.Fatal("Failed to load the INI file:", err)
	}

	// this code below will take all the datasources specified in the ini and populate the filled ones into the yaml
	yamlDataSources := make([]*config.DataSource, 0)

	for _, v := range iniConfig.datasrcConfigs {
		if len(v.creds) == 0 {
			continue // Skip to the next iteration if there are no credentials
		}

		creds := make(map[string]*config.Credentials)
		for credKey, credValue := range v.creds {
			creds[credKey] = &config.Credentials{
				Name:     credValue.Name,
				Username: credValue.Username,
				Password: credValue.Password,
				Apikey:   credValue.Key,
				Secret:   credValue.Secret,
			}
		}

		yamlDataSources = append(yamlDataSources, &config.DataSource{
			Name:  v.Name,
			TTL:   v.TTL,
			Creds: creds,
		})
	}

	// this part of the code will populate the options only if theyre populated in the ini
	options := make(map[string]interface{})

	if len(iniConfig.Resolvers) > 0 {
		options["resolvers"] = iniConfig.Resolvers
	}

	if iniConfig.BruteForcing {
		bruteforce := make(map[string]interface{})
		bruteforce["enabled"] = iniConfig.BruteForcing

		if len(iniConfig.Bruteforcelist) > 0 {
			bruteforce["wordlist"] = iniConfig.Bruteforcelist
		}

		options["bruteforce"] = bruteforce
	}

	if iniConfig.Alterations {
		alterations := make(map[string]interface{})
		alterations["enabled"] = iniConfig.Alterations

		if len(iniConfig.Alterationslist) > 0 {
			alterations["wordlist"] = iniConfig.Alterationslist
		}

		options["alterations"] = alterations
	}

	// this part of the code initializes the yamlconfig file with the values
	yamlConfig := config.Config{
		Scope: &config.Scope{
			Domains:     iniConfig.domains,
			IP:          iniConfig.Addresses,
			ASNs:        iniConfig.ASNs,
			CIDRStrings: iniConfig.CIDRs,
			Ports:       iniConfig.Ports,
			Blacklist:   iniConfig.Blacklist,
		},
		Options: options,
	}

	// if the databse is present in the ini, then store the first url.
	if len(iniConfig.GraphDBs) > 0 {
		yamlConfig.Options["database"] = iniConfig.GraphDBs[0].URL
	}

	// this part of the code initializes the yamlDataSrcConfigs file with the values
	yamlDataSrcConfigs := config.DataSourceConfig{
		Datasources: yamlDataSources,
		GlobalOptions: map[string]int{
			"minimum_ttl": iniConfig.MinimumTTL,
		},
	}

	// marshals and outputs it into a file

	output, err := yaml.Marshal(yamlDataSrcConfigs)
	if err != nil {
		log.Println("failed to marshal the yaml:", err)
	} else {
		yamlConfig.Options["datasources"] = datasrcFile
		err = os.WriteFile(datasrcFile, output, 0644)
		if err != nil {
			log.Println("Failed to write datasources file:", err)
		} else {
			fmt.Println(b.Sprint("Wrote data sources file successfully at: ") + p.Sprint(datasrcFile))
		}
	}

	output, err = yaml.Marshal(&yamlConfig)
	if err != nil {
		log.Println("failed to marshal the yaml:", err)
	} else {
		err = os.WriteFile(configFile, output, 0644)
		if err != nil {
			log.Println("Failed to write config file:", err)
		} else {
			fmt.Println(b.Sprint("Wrote config file successfully at ") + p.Sprint(configFile))
		}
	}
}
