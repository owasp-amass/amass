// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/secrets"
)

func TestDataSourceKeyLinkToTheStore(t *testing.T) {
	fx := newOperatorFixture(t)
	enc, _ := secrets.NewKey()
	key, _ := secrets.ParseKey(enc)
	store := secrets.Open(&secrets.FakeDB{}, key)
	fx.op.Secrets, fx.op.KeyLinks.Store = store, store
	cs := connect(t, fx.url, operatorToken, nil)

	text, isErr := call(t, cs, ToolDataSourceKey, map[string]any{"source": "Shodan"})
	if isErr {
		t.Fatal(text)
	}
	var link struct{ URL string }
	if err := json.Unmarshal([]byte(text), &link); err != nil {
		t.Fatal(err)
	}

	page, err := http.Get(link.URL)
	if err != nil {
		t.Fatal(err)
	}
	form, _ := io.ReadAll(page.Body)
	_ = page.Body.Close()
	if !strings.Contains(string(form), "stored encrypted in the Amass database") ||
		strings.Contains(string(form), "Account label") {
		t.Errorf("the form does not say the key goes to the database:\n%s", form)
	}

	resp, err := http.PostForm(link.URL, url.Values{"apikey": {"sk-test-123"}, "account": {"account"}})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || strings.Contains(string(body), "sk-test") {
		t.Fatalf("post = %d %s", resp.StatusCode, body)
	}

	// the key went to the store, not the datasources file
	if values, _, _ := store.Values(); values["Shodan"]["apikey"] != "sk-test-123" {
		t.Fatalf("store = %v", values)
	}
	if data, _ := os.ReadFile(fx.sources); strings.Contains(string(data), "sk-test-123") {
		t.Fatalf("the key was written to the datasources file:\n%s", data)
	}

	text, _ = call(t, cs, ToolDataSources, map[string]any{})
	var st struct {
		Configured []string          `json:"configured"`
		From       map[string]string `json:"credentials_from"`
	}
	if err := json.Unmarshal([]byte(text), &st); err != nil || len(st.Configured) != 1 ||
		st.From["Shodan"] != secrets.FromDatabase {
		t.Fatalf("data sources = %s", text)
	}
}
