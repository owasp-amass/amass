// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// Valid mock YAML configuration for testing
var validMockConfigYAML = []byte(`
options:
  engine: "http://username:password@127.0.0.1:80/path?option1=value1"
`)

// Invalid mock YAML configuration (non-string engine value)
var invalidTypeMockConfigYAML = []byte(`
options:
  engine: 123
`)

// Invalid mock YAML configuration (malformed YAML)
var malformedMockConfigYAML = []byte(`
	options
  engine "http://username:password@127.0.0.1:80/path?option1=value1"
`)

func TestLoadEngineSettings_ValidConfig(t *testing.T) {
	c := NewConfig()

	err := yaml.Unmarshal(validMockConfigYAML, &c)
	require.NoError(t, err, "Unmarshalling valid YAML should not produce an error")

	err = c.loadEngineSettings(c)
	assert.NoError(t, err, "loadEngineSettings should not return an error with valid config")
	assert.NotNil(t, c.EngineAPI, "EngineAPI should not be nil after loading settings")
}

func TestLoadEngineSettings_InvalidType(t *testing.T) {
	c := NewConfig()

	err := yaml.Unmarshal(invalidTypeMockConfigYAML, &c)
	require.NoError(t, err, "Unmarshalling invalid type YAML should not produce an error")

	err = c.loadEngineSettings(c)
	assert.Error(t, err, "loadEngineSettings should return an error if 'engine' type is not string")
}

func TestLoadEngineSettings_MalformedYAML(t *testing.T) {
	c := NewConfig()

	err := yaml.Unmarshal(malformedMockConfigYAML, &c)
	assert.Error(t, err, "Unmarshalling malformed YAML should produce an error")
}

func TestLoadEngineURI_ValidURI(t *testing.T) {
	c := NewConfig()

	err := yaml.Unmarshal(validMockConfigYAML, &c)
	require.NoError(t, err, "Unmarshalling valid YAML should not produce an error")

	_ = c.loadEngineSettings(c)

	assert.Equal(t, "http", c.EngineAPI.Scheme, "Scheme should be 'http'")
	assert.Equal(t, "username", c.EngineAPI.Username, "Username should be 'username'")
	assert.Equal(t, "password", c.EngineAPI.Password, "Password should be 'password'")
	assert.Equal(t, "127.0.0.1", c.EngineAPI.Host, "Host should be 'hostname'")
	assert.Equal(t, "80", c.EngineAPI.Port, "Port should be 'port'")
	assert.Equal(t, "path", c.EngineAPI.Path, "Path should be 'path'")
	assert.Equal(t, "option1=value1", c.EngineAPI.Options, "Options should be 'option1=value1'")
}

func TestLoadEngineURI_InvalidURI(t *testing.T) {
	c := NewConfig()

	// Set 'engine' option to an invalid URI
	c.Options["engine"] = "http:://invalid-uri"

	err := c.loadEngineSettings(c)
	assert.Error(t, err, "loadEngineSettings should return an error for invalid URI")
}

func TestLoadEngineURI_MissingScheme(t *testing.T) {
	c := NewConfig()

	// Set 'engine' option to a URI missing a scheme
	c.Options["engine"] = "username:password@hostname:port/path?option1=value1"

	err := c.loadEngineSettings(c)
	assert.Error(t, err, "loadEngineSettings should return an error for missing scheme in URI")
}
func TestLoadEngineEnvSettings_ValidEnvSettings(t *testing.T) {
	c := NewConfig()

	// Set the required environment variables
	os.Setenv(engineHost, "127.0.0.1")
	os.Setenv(engineUser, "username")
	os.Setenv(enginePass, "password")
	os.Setenv(engineScheme, "http")
	os.Setenv(enginePort, "80")
	os.Setenv(enginePath, "path")

	err := c.LoadEngineEnvSettings()
	assert.NoError(t, err, "LoadEngineEnvSettings should not return an error with valid environment settings")
	assert.NotNil(t, c.EngineAPI, "EngineAPI should not be nil after loading environment settings")

	// Verify the loaded EngineAPI values
	assert.Equal(t, "http", c.EngineAPI.Scheme, "Scheme should be 'http'")
	assert.Equal(t, "username", c.EngineAPI.Username, "Username should be 'username'")
	assert.Equal(t, "password", c.EngineAPI.Password, "Password should be 'password'")
	assert.Equal(t, "127.0.0.1", c.EngineAPI.Host, "Host should be '127.0.0.1'")
	assert.Equal(t, "80", c.EngineAPI.Port, "Port should be '80'")
	assert.Equal(t, "path", c.EngineAPI.Path, "Path should be 'path'")
}

func TestLoadEngineEnvSettings_MissingEnvSettings(t *testing.T) {
	c := NewConfig()

	// Unset the required environment variables
	os.Unsetenv(engineHost)
	os.Unsetenv(engineUser)
	os.Unsetenv(enginePass)
	os.Unsetenv(engineScheme)
	os.Unsetenv(enginePort)
	os.Unsetenv(enginePath)

	err := c.LoadEngineEnvSettings()
	_ = c.loadEngineURI(c.EngineAPI.URL)
	assert.Nil(t, err, "LoadEngineEnvSettings shouldn't return an error since default values are in place")
	assert.NotEmpty(t, c.EngineAPI, "EngineAPI should be properly populated")
}
