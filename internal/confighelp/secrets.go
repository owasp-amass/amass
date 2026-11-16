// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package confighelp

import (
	"gopkg.in/yaml.v3"
)

// redacted replaces a masked credential value.
const redacted = "***"

// RedactSecrets returns content with every data source credential value
// masked, so a configuration can be shown to a language model without its
// secrets. Keys, comments and the rest of the document are preserved. An
// empty or comment-only document comes back unchanged.
func RedactSecrets(content string) (string, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(content), &doc); err != nil {
		return "", err
	}
	if len(doc.Content) == 0 {
		return content, nil
	}

	walkCreds(root(&doc), maskScalars)
	out, err := yaml.Marshal(&doc)
	if err != nil {
		return "", err
	}

	return string(out), nil
}

// ContainsSecrets reports whether content sets any data source credential.
// apply_config refuses such content: a model never supplies credentials; the
// operator enters them at a one-time local link.
func ContainsSecrets(content string) bool {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(content), &doc); err != nil {
		return false
	}
	if len(doc.Content) == 0 {
		return false
	}

	found := false
	walkCreds(root(&doc), func(n *yaml.Node) {
		if hasNonEmptyScalar(n) {
			found = true
		}
	})

	return found
}

// hasNonEmptyScalar reports whether any scalar reachable from n holds a
// value: a credential block sets a secret only when one of its leaves does.
func hasNonEmptyScalar(n *yaml.Node) bool {
	if n == nil {
		return false
	}

	switch n.Kind {
	case yaml.ScalarNode:
		return n.Value != ""
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			if hasNonEmptyScalar(n.Content[i+1]) {
				return true
			}
		}
	case yaml.SequenceNode:
		for _, c := range n.Content {
			if hasNonEmptyScalar(c) {
				return true
			}
		}
	}

	return false
}

// root returns the mapping node at the top of a parsed document, or nil.
func root(doc *yaml.Node) *yaml.Node {
	if doc == nil || len(doc.Content) == 0 {
		return nil
	}

	n := doc.Content[0]
	if n.Kind != yaml.MappingNode {
		return nil
	}

	return n
}

// walkCreds applies fn to the value nodes under each datasources[].creds in a
// configuration's root mapping.
func walkCreds(rootMap *yaml.Node, fn func(*yaml.Node)) {
	if rootMap == nil {
		return
	}

	sources := mapValue(rootMap, "datasources")
	if sources == nil || sources.Kind != yaml.SequenceNode {
		return
	}
	for _, item := range sources.Content {
		if item.Kind != yaml.MappingNode {
			continue
		}
		if creds := mapValue(item, "creds"); creds != nil {
			fn(creds)
		}
	}
}

// mapValue returns the value node for key in a mapping node, or nil.
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

// maskScalars replaces every scalar value reachable from n with the redaction
// marker, leaving mapping keys in place.
func maskScalars(n *yaml.Node) {
	if n == nil {
		return
	}

	switch n.Kind {
	case yaml.ScalarNode:
		if n.Value != "" {
			n.Value = redacted
			n.Tag = "!!str"
			n.Style = 0
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			maskScalars(n.Content[i+1])
		}
	case yaml.SequenceNode:
		for _, c := range n.Content {
			maskScalars(c)
		}
	case yaml.AliasNode:
		// An alias to masked content is already covered; nothing to do.
	default:
	}
}
