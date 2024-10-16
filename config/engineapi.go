// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

// EngAPI structure holds various components necessary for establishing a connection with an Engine API.
// It includes fields for the scheme (http or https), the full API URL, authentication credentials (username, password),
// host and port information, the specific path (name) of the API, and any extra options that may be used during the connection.
type EngAPI struct {
	Scheme   string // Engine API scheme (http, https)
	URL      string // Full URI to the Engine API
	Username string // Username for authentication
	Password string // Password for authentication
	Host     string // Host of the Engine API
	Port     string // Port of the Engine API
	Path     string // Name of the Engine API
	Options  string // Extra options used while connecting to the Engine API
}

const (
	engineUser   = "AMASS_ENGINE_USER"
	enginePass   = "AMASS_ENGINE_PASSWORD"
	engineHost   = "AMASS_ENGINE_HOST"
	enginePort   = "AMASS_ENGINE_PORT"
	enginePath   = "AMASS_ENGINE_PATH"
	engineScheme = "AMASS_ENGINE_SCHEME"
)

// loadEngineSettings is responsible for extracting the "engine" URL from the application's configuration
// and initializing the EngAPI structure. It performs several checks such as ensuring the configuration options
// are initialized and the "engine" key is present and of type string. If any of these checks fail, an error is returned.
func (c *Config) loadEngineSettings(cfg *Config) error {
	// Check if configuration options are initialized; if not, return an error.
	if c.Options == nil {
		return fmt.Errorf("config options are not initialized")
	}
	// Attempt to retrieve the "engine" value from the configuration options.
	apiURIInterface, ok := c.Options["engine"]
	if !ok {
		_ = c.LoadEngineEnvSettings()
		return nil
	}
	// Assert that the "engine" option is of type string; if not, return an error specifying the incorrect type received.
	apiURI, ok := apiURIInterface.(string)
	if !ok {
		return fmt.Errorf("expected 'engine' to be a string, got %T", apiURIInterface)
	}
	// Load the Engine API URI information into the EngAPI structure.
	// If there's an error during this process, it's returned to the calling function.
	if err := c.loadEngineURI(apiURI); err != nil {
		return err
	}
	return nil
}

// LoadEngineEnvSettings initializes the EngAPI structure with the Environment variables.
func (c *Config) LoadEngineEnvSettings() error {
	apiURI := ""
	eng := &EngAPI{}

	h := "localhost"
	if henv, set := os.LookupEnv(engineHost); set {
		h = henv
	}
	eng.Host = h
	u := ""
	if uEnv, set := os.LookupEnv(engineUser); set {
		eng.Username = uEnv
		u = uEnv + "@"
	}
	p := ""
	if penv, set := os.LookupEnv(enginePass); set {
		eng.Password = penv
		p = ":" + penv + "@"
	}
	scheme := "http"
	if s, set := os.LookupEnv(engineScheme); set {
		scheme = s
	}
	eng.Scheme = scheme
	port := "4000"
	if pEnv, set := os.LookupEnv(enginePort); set {
		port = pEnv
	}
	eng.Port = port
	path := "graphql"
	if pEnv, set := os.LookupEnv(enginePath); set {
		path = pEnv
	}
	eng.Path = path
	if p != "" {
		u = u[:len(u)-1]
	}
	apiURI = scheme + "://" + u + p + h + ":" + port + "/" + path
	eng.URL = apiURI

	c.EngineAPI = eng
	return nil
}

// loadEngineURI takes the Engine API's URI as a string, parses it, and populates the EngAPI structure with the URI's components.
// It performs validations to ensure the URI contains a valid scheme and hostname. If parsing fails or any validation check doesn't pass,
// an error is returned. It also handles extracting authentication information and any additional options provided in the URI query.
func (c *Config) loadEngineURI(apiURI string) error {
	// Parse the raw URI string to a url.URL object. If the URI is malformed, an error is returned.
	u, err := url.Parse(apiURI)
	if err != nil {
		return err
	}
	// Check for valid scheme
	if u.Scheme == "" {
		return fmt.Errorf("missing scheme in database URI")
	}
	// Check for reachable hostname
	if u.Hostname() == "" {
		return fmt.Errorf("missing hostname in database URI")
	}
	// If the path is present in the URI and is more than just a "/", it's trimmed and used.
	// If the path is empty or just a "/", it defaults to an empty string.
	apiURIPath := ""
	// Only get the api file path name if it's not empty or a single slash
	if u.Path != "" && u.Path != "/" {
		apiURIPath = strings.TrimPrefix(u.Path, "/")
	}
	// Initialize a new EngAPI object with data from the parsed URI.
	api := &EngAPI{
		URL:      apiURI,
		Scheme:   u.Scheme,
		Username: u.User.Username(),
		Path:     apiURIPath,
		Host:     u.Hostname(), // Hostname without port
		Port:     u.Port(),     // Get port
	}
	// If a password is set in the URI, it's extracted and stored in the EngAPI object.
	password, isSet := u.User.Password()
	if isSet {
		api.Password = password
	}
	// If there are query parameters present in the URI, they are parsed and encoded as a string,
	// then stored in the EngAPI object's Options field. If parsing fails, an error is returned.
	if u.RawQuery != "" {
		queryParams, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			return fmt.Errorf("unable to parse engine API URI query parameters: %v", err)
		}
		api.Options = queryParams.Encode() // Encode url.Values to a string
	}
	// The Config's EngineAPI field is set to the newly created EngAPI object.
	c.EngineAPI = api
	return nil
}
