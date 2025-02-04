// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/owasp-amass/amass/v4/engine"
	"github.com/owasp-amass/amass/v4/engine/plugins"
	slogcommon "github.com/samber/slog-common"
	slogsyslog "github.com/samber/slog-syslog/v2"
)

func main() {
	var logdir string
	flag.StringVar(&logdir, "log-dir", "", "path to the log directory")
	flag.Parse()

	l := selectLogger(logdir)
	e, err := engine.NewEngine(l)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start the engine: %v", err)
		os.Exit(1)
	}
	defer e.Shutdown()

	if err := plugins.LoadAndStartPlugins(e.Registry); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start the plugins: %v", err)
		os.Exit(1)
	}

	if err := e.Registry.BuildPipelines(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to build the handler pipelines: %v", err)
		os.Exit(1)
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(quit)
	<-quit
	l.Info("Terminating the collection engine")
}

func selectLogger(dir string) *slog.Logger {
	if dir != "" {
		return setupFileLogger(dir)
	}
	if l := setupSyslogLogger(); l != nil {
		return l
	}
	if l := setupFileLogger(""); l != nil {
		return l
	}
	return slog.New(slog.NewTextHandler(os.Stdout, nil))
}

func setupFileLogger(dir string) *slog.Logger {
	if dir != "" {
		if err := os.MkdirAll(dir, 0640); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create the log directory: %v", err)
		}
	}

	filename := fmt.Sprintf("amass_engine_%s.log", time.Now().Format("2006-01-02T15:04:05"))
	f, err := os.OpenFile(filepath.Join(dir, filename), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
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
