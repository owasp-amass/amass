// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"

	afmt "github.com/owasp-amass/amass/v5/internal/afmt"
	slogcommon "github.com/samber/slog-common"
	slogsyslog "github.com/samber/slog-syslog/v2"
)

func WriteLogMessage(l *slog.Logger, message string) error {
	record, err := afmt.JSONLogToRecord(message)
	if err != nil {
		return err
	}

	ctx := context.Background()
	if l.Handler().Enabled(ctx, record.Level) {
		return l.Handler().Handle(ctx, record)
	}

	return errors.New("logger handler is not enabled")
}

func NewFileLogger(dir, logfile string) (*slog.Logger, error) {
	if logfile == "" {
		return nil, fmt.Errorf("no log file specified")
	}

	if dir != "" {
		if err := os.MkdirAll(dir, 0640); err != nil {
			return nil, fmt.Errorf("failed to create the log directory: %v", err)
		}
	}

	f, err := os.OpenFile(filepath.Join(dir, logfile), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open the log file: %v", err)
	}

	return slog.New(slog.NewJSONHandler(f, nil)), nil
}

func NewSyslogLogger() (*slog.Logger, error) {
	port := os.Getenv("SYSLOG_PORT")
	host := strings.ToLower(os.Getenv("SYSLOG_HOST"))
	transport := strings.ToLower(os.Getenv("SYSLOG_TRANSPORT"))

	if host == "" {
		return nil, fmt.Errorf("no syslog host specified")
	}
	if port == "" {
		port = "514"
	}
	if transport == "" {
		transport = "udp"
	}

	writer, err := net.Dial(transport, net.JoinHostPort(host, port))
	if err != nil {
		return nil, fmt.Errorf("failed to create the connection to the log server: %v", err)
	}

	return slog.New(slogsyslog.Option{
		Level:     slog.LevelInfo,
		Converter: syslogConverter,
		Writer:    writer,
	}.NewSyslogHandler()), nil
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
