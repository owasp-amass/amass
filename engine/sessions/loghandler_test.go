// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// A session's record reaches both its subscribers and the engine's log, with
// the session attribute and the plugin group on each.
func TestTeeHandlerWritesToEveryHandler(t *testing.T) {
	var stream, engine bytes.Buffer
	log := slog.New(newTeeHandler(
		slog.NewJSONHandler(&stream, nil),
		slog.NewJSONHandler(&engine, nil),
	)).With("session", "s1")

	log.Info("archived URLs stored", "count", 3, slog.Group("plugin", "name", "Wayback"))

	for name, buf := range map[string]*bytes.Buffer{"stream": &stream, "engine": &engine} {
		got := buf.String()
		for _, want := range []string{`"msg":"archived URLs stored"`, `"session":"s1"`, `"count":3`,
			`"plugin":{"name":"Wayback"}`} {
			if !strings.Contains(got, want) {
				t.Errorf("%s log %q lacks %s", name, got, want)
			}
		}
	}
}

// A level one handler drops is still written to the other.
func TestTeeHandlerHonorsEachLevel(t *testing.T) {
	var debug, info bytes.Buffer
	log := slog.New(newTeeHandler(
		slog.NewJSONHandler(&debug, &slog.HandlerOptions{Level: slog.LevelDebug}),
		slog.NewJSONHandler(&info, nil),
	))

	log.Debug("detail")
	if debug.Len() == 0 || info.Len() != 0 {
		t.Errorf("debug record: debug handler %q, info handler %q", debug.String(), info.String())
	}
}

// Nil handlers are skipped, and a single handler is used as it is.
func TestNewTeeHandlerSkipsNil(t *testing.T) {
	h := slog.NewJSONHandler(&bytes.Buffer{}, nil)
	if got := newTeeHandler(h, nil); got != slog.Handler(h) {
		t.Errorf("one handler wrapped: %T", got)
	}
}
