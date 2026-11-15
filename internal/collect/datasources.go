// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package collect

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/owasp-amass/amass/v5/config"
	"gopkg.in/yaml.v3"
)

// SourceStatus says whether a data source has credentials configured. It
// never carries the credentials themselves.
type SourceStatus struct {
	Name       string `json:"name"`
	Configured bool   `json:"configured"`
	Accounts   int    `json:"accounts,omitempty"`
}

// commentedSource finds the data sources the default datasources.yaml lists
// commented out ("#  - name: Shodan"), which are available but unused.
var commentedSource = regexp.MustCompile(`(?m)^\s*#\s*-\s*name:\s*([A-Za-z0-9][\w.-]*)\s*$`)

// DataSourcesPath is the datasources file a configuration names.
func DataSourcesPath(cfg *config.Config) (string, error) {
	if cfg == nil {
		return "", errors.New("no configuration")
	}

	raw, ok := cfg.Options["datasources"].(string)
	if !ok || raw == "" {
		return "", errors.New("the configuration names no datasources file (options.datasources)")
	}

	return cfg.AbsPathFromConfigDir(raw)
}

// DataSourceStatus lists the data sources in a datasources file: those with
// at least one set of credentials, and those listed but commented out or
// without credentials.
func DataSourceStatus(path string) ([]SourceStatus, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var dsc config.DataSourceConfig
	if err := yaml.Unmarshal(data, &dsc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	byName := map[string]*SourceStatus{}
	for _, ds := range dsc.Datasources {
		if ds == nil || ds.Name == "" {
			continue
		}

		s := &SourceStatus{Name: ds.Name}
		for _, c := range ds.Creds {
			if c != nil && (c.Apikey != "" || c.Secret != "" || c.Password != "" || c.Username != "") {
				s.Accounts++
			}
		}

		s.Configured = s.Accounts > 0
		byName[strings.ToLower(ds.Name)] = s
	}
	for _, m := range commentedSource.FindAllSubmatch(data, -1) {
		name := string(m[1])
		if _, ok := byName[strings.ToLower(name)]; !ok {
			byName[strings.ToLower(name)] = &SourceStatus{Name: name}
		}
	}

	out := make([]SourceStatus, 0, len(byName))
	for _, s := range byName {
		out = append(out, *s)
	}

	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out, nil
}

// SetDataSourceCredentials stores credentials for a data source's account in
// a datasources file, replacing that account's earlier credentials and
// keeping the file's other entries and comments. The file is rewritten in
// place, since it may be a single bind-mounted file.
func SetDataSourceCredentials(path, source, account string, cred config.Credentials) error {
	source, account = strings.TrimSpace(source), strings.TrimSpace(account)
	if source == "" || strings.ContainsAny(source, "\n\r:#") {
		return errors.New("invalid data source name")
	}
	if account == "" {
		account = "account"
	}
	if cred.Apikey == "" && cred.Secret == "" && cred.Username == "" && cred.Password == "" {
		return errors.New("no credentials given")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if doc.Kind == 0 {
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}}
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("%s is not a YAML mapping", path)
	}

	root := doc.Content[0]
	list := mapValue(root, "datasources")
	if list == nil {
		list = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		root.Content = append(root.Content, scalar("datasources"), list)
	} else if list.Kind != yaml.SequenceNode {
		// "datasources:" with every entry commented out parses as null.
		comments := [3]string{list.HeadComment, list.LineComment, list.FootComment}
		*list = yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", HeadComment: comments[0],
			LineComment: comments[1], FootComment: comments[2]}
	}

	var entry *yaml.Node
	for _, item := range list.Content {
		if n := mapValue(item, "name"); n != nil && strings.EqualFold(n.Value, source) {
			entry = item
			break
		}
	}
	if entry == nil {
		entry = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{scalar("name"), scalar(source)}}
		list.Content = append(list.Content, entry)
	}

	creds := mapValue(entry, "creds")
	if creds == nil || creds.Kind != yaml.MappingNode {
		creds = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		setMapValue(entry, "creds", creds)
	}

	acct := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for _, kv := range [][2]string{{"username", cred.Username}, {"password", cred.Password},
		{"apikey", cred.Apikey}, {"secret", cred.Secret}} {
		if kv[1] != "" {
			acct.Content = append(acct.Content, scalar(kv[0]), quoted(kv[1]))
		}
	}

	setMapValue(creds, account, acct)

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return err
	}

	_ = enc.Close()

	// Check the result loads before replacing the file.
	var check config.DataSourceConfig
	if err := yaml.Unmarshal(buf.Bytes(), &check); err != nil {
		return fmt.Errorf("the updated file would not load: %w", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	return os.WriteFile(path, buf.Bytes(), info.Mode().Perm())
}

func scalar(v string) *yaml.Node { return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v} }

func quoted(v string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v, Style: yaml.DoubleQuotedStyle}
}

func mapValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}

	return nil
}

func setMapValue(m *yaml.Node, key string, v *yaml.Node) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content[i+1] = v
			return
		}
	}

	m.Content = append(m.Content, scalar(key), v)
}
