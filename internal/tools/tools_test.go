// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/resources"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
)

func TestCreateOutputDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "b")
	if err := CreateOutputDirectory(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0755 {
		t.Fatalf("output directory = %v, %v; want a 0755 directory", info, err)
	}
	// an existing directory is fine
	if err := CreateOutputDirectory(dir); err != nil {
		t.Errorf("second call: %v", err)
	}
}

func TestCreateDefaultConfigFiles(t *testing.T) {
	dir := t.TempDir()
	// an existing file is left alone
	kept := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(kept, []byte("mine"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := CreateDefaultConfigFiles(dir); err != nil {
		t.Fatal(err)
	}
	for _, name := range resources.DefaultFilesList {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("%s was not created: %v", name, err)
			continue
		}
		if name == "config.yaml" {
			if string(got) != "mine" {
				t.Error("an existing config.yaml was overwritten")
			}
			continue
		}
		want, err := resources.GetResourceFileData(name)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s differs from the embedded file (%v)", name, err)
		}
	}
}

func TestNewFileLogger(t *testing.T) {
	if _, err := NewFileLogger(t.TempDir(), ""); err == nil {
		t.Error("a logger without a file name was created")
	}

	// the log directory is created, and must be usable for the file
	dir := filepath.Join(t.TempDir(), "logs", "amass")
	l, err := NewFileLogger(dir, "amass.log")
	if err != nil {
		t.Fatal(err)
	}
	l.Info("hello", "name", "example.com")
	data, err := os.ReadFile(filepath.Join(dir, "amass.log"))
	if err != nil || !strings.Contains(string(data), `"msg":"hello"`) ||
		!strings.Contains(string(data), `"name":"example.com"`) {
		t.Errorf("log file = %q, %v", data, err)
	}
}

func TestWriteLogMessage(t *testing.T) {
	var buf bytes.Buffer
	l := slog.New(slog.NewJSONHandler(&buf, nil))

	if err := WriteLogMessage(l, `{"level":"INFO","msg":"from the engine","name":"example.com"}`); err != nil {
		t.Fatal(err)
	}
	if out := buf.String(); !strings.Contains(out, `"msg":"from the engine"`) ||
		!strings.Contains(out, `"name":"example.com"`) {
		t.Errorf("relayed record = %q", out)
	}
	if err := WriteLogMessage(l, "not json"); err == nil {
		t.Error("a malformed message was relayed")
	}
	// a record below the handler's level is not written
	if err := WriteLogMessage(l, `{"level":"DEBUG","msg":"quiet"}`); err == nil {
		t.Error("a record below the handler's level was written")
	}
}

func TestNewSyslogLoggerNeedsAHost(t *testing.T) {
	t.Setenv("SYSLOG_HOST", "")
	if _, err := NewSyslogLogger(); err == nil {
		t.Error("a syslog logger was created without a host")
	}
}

func TestNewGraph(t *testing.T) {
	if db := NewGraph("unknown", "x", ""); db != nil {
		t.Error("an unknown system opened a database")
	}
	db := NewGraph("local", filepath.Join(t.TempDir(), "asset.db"), "")
	if db == nil {
		t.Fatal("the local database was not opened")
	}
	defer func() { _ = db.Close() }()
	if db.Type() != sqlite3.SQLite {
		t.Errorf("database type = %q", db.Type())
	}
}

func TestOpenGraphDatabaseLocal(t *testing.T) {
	cfg := config.NewConfig()
	cfg.Dir = t.TempDir()
	db := OpenGraphDatabase(cfg)
	if db == nil {
		t.Fatal("the default local database was not opened")
	}
	defer func() { _ = db.Close() }()
	if _, err := os.Stat(filepath.Join(cfg.Dir, "asset.db")); err != nil {
		t.Errorf("asset.db was not created in the output directory: %v", err)
	}
}
