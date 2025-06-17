// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package assoc

import (
	"fmt"
	"strings"
	"time"

	oam "github.com/owasp-amass/open-asset-model"
)

const (
	DirectionIncoming = iota
	DirectionOutgoing
)

var (
	tripleFields = []string{"subject", "predicate", "object"}
)

type Triple struct {
	Direction int // 0 for incoming, 1 for outgoing
	Subject   *Node
	Predicate *Predicate
	Object    *Node
}

type Node struct {
	Key        string
	Type       oam.AssetType
	Since      time.Time
	Attributes map[string]string
	Properties []*Property
}

type Predicate struct {
	Label      string
	Type       oam.RelationType
	Since      time.Time
	Attributes map[string]string
	Properties []*Property
}

type Property struct {
	Name       string
	Since      time.Time
	Type       oam.PropertyType
	Attributes map[string]string
}

func (n *Node) IsWildcard() bool {
	return n.Key == "*" && (n.Type != oam.AssetType("*") || len(n.Attributes) == 0)
}

func (p *Predicate) IsWildcard() bool {
	return p.Label == "*" && (p.Type != oam.RelationType("*") || len(p.Attributes) == 0)
}

func ParseTriple(triple string) (*Triple, error) {
	tristrs, direction, err := splitTriple(triple)
	if err != nil {
		return nil, fmt.Errorf("invalid triple format: %v", err)
	}

	subject, err := parseNode(tristrs[0])
	if err != nil {
		return nil, fmt.Errorf("invalid subject: %v", err)
	}

	predicate, err := parsePredicate(tristrs[1])
	if err != nil {
		return nil, fmt.Errorf("invalid predicate: %v", err)
	}

	object, err := parseNode(tristrs[2])
	if err != nil {
		return nil, fmt.Errorf("invalid object: %v", err)
	}

	if subject.Type != "*" && predicate.Type != "*" && !predicate.IsWildcard() && object.Type != "*" {
		if direction == DirectionOutgoing && !oam.ValidRelationship(subject.Type, predicate.Label, predicate.Type, object.Type) {
			return nil, fmt.Errorf("%s-%s->%s is not a valid triple in the Open Asset Model", subject.Type, predicate.Label, object.Type)
		} else if direction == DirectionIncoming && !oam.ValidRelationship(object.Type, predicate.Label, predicate.Type, subject.Type) {
			return nil, fmt.Errorf("%s<-%s-%s is not a valid triple in the Open Asset Model", object.Type, predicate.Label, subject.Type)
		}
	}

	return &Triple{
		Direction: direction,
		Subject:   subject,
		Predicate: predicate,
		Object:    object,
	}, nil
}

func splitTriple(triple string) ([]string, int, error) {
	start := 0
	var results []string
	direction := DirectionOutgoing

	for _, i := range []int{0, 1, 2} {
		substr := triple[start:]

		sidx := strings.Index(substr, "<")
		if sidx == -1 {
			return nil, direction, fmt.Errorf("triple must contain an opening angle bracket for the %s", tripleFields[i])
		}
		sidx += 1 // move past the opening angle bracket

		eidx := strings.Index(substr, ">")
		if eidx == -1 {
			return nil, direction, fmt.Errorf("triple must contain a closing angle bracket for the %s", tripleFields[i])
		}
		if eidx <= sidx {
			return nil, direction, fmt.Errorf("the %s must contain a closing angle bracket after an opening angle bracket", tripleFields[i])
		}
		results = append(results, strings.TrimSpace(substr[sidx:eidx]))

		start += eidx + 1 // move past the closing angle bracket
		substr = triple[start:]

		switch i {
		case 0:
			if idx := strings.Index(substr, "<-"); idx != -1 && (idx == 0 || idx == 1) {
				direction = DirectionIncoming
				start += idx + 2 // move past the "<-"
			} else if idx := strings.Index(substr, "-"); idx != -1 && (idx == 0 || idx == 1) {
				start += idx + 1 // move past the "-"
			} else {
				return nil, direction, fmt.Errorf("triple must contain a hyphen or '<-' after the subject")
			}
		case 1:
			if idx := strings.Index(substr, "->"); idx != -1 && (idx == 0 || idx == 1) {
				if direction == DirectionIncoming {
					return nil, direction, fmt.Errorf("triple cannot have both '<-' and '->'")
				}
				start += idx + 2 // move past the "<-"
			} else if idx := strings.Index(substr, "-"); idx != -1 && (idx == 0 || idx == 1) {
				if direction == DirectionOutgoing {
					return nil, direction, fmt.Errorf("triple must have a direction specified with '<-' or '->'")
				}
				start += idx + 1 // move past the "-"
			} else {
				return nil, direction, fmt.Errorf("triple must contain a hyphen or '<-' after the predicate")
			}
		}
	}

	return results, direction, nil
}

func parseNode(nodestr string) (*Node, error) {
	parts := strings.Split(nodestr, ",")
	if len(parts) == 1 && parts[0] == "*" {
		return &Node{
			Key:        "*",
			Type:       oam.AssetType("*"),
			Attributes: make(map[string]string),
		}, nil
	}

	node := &Node{Attributes: make(map[string]string)}
	for i, part := range parts {
		if i == 0 && strings.TrimSpace(part) == "*" {
			node.Key = "*"
			node.Type = oam.AssetType("*")
			continue
		}

		kv := strings.Split(part, ":")
		if len(kv) != 2 {
			return nil, fmt.Errorf("%s must be a key/value pair separated by a ':'", part)
		}
		k := strings.TrimSpace(kv[0])
		v := strings.TrimSpace(kv[1])

		if i == 0 {
			atype, err := keyToAssetType(k)
			if err != nil {
				return nil, err
			}
			node.Type = atype
			node.Key = v
		} else if strings.EqualFold(k, "prop") {
			prop, err := parseProperty(v)
			if err != nil {
				return nil, fmt.Errorf("invalid property: %v", err)
			}
			node.Properties = append(node.Properties, prop)
		} else if strings.EqualFold(k, "since") {
			since, err := time.Parse(time.DateOnly, v)
			if err != nil {
				return nil, err
			}
			node.Since = since
		} else {
			node.Attributes[k] = v
		}
	}

	return node, nil
}

func keyToAssetType(key string) (oam.AssetType, error) {
	for _, atype := range oam.AssetList {
		if strings.EqualFold(string(atype), key) {
			return atype, nil
		}
	}
	return "", fmt.Errorf("%s does not match any asset type", key)
}

func parsePredicate(predstr string) (*Predicate, error) {
	parts := strings.Split(predstr, ",")
	if len(parts) == 1 && parts[0] == "*" {
		return &Predicate{
			Label:      "*",
			Type:       oam.RelationType("*"),
			Attributes: make(map[string]string),
		}, nil
	}

	pred := &Predicate{Attributes: make(map[string]string)}
	for i, part := range parts {
		if i == 0 && strings.TrimSpace(part) == "*" {
			pred.Label = "*"
			pred.Type = oam.RelationType("*")
			continue
		}

		kv := strings.Split(part, ":")
		if len(kv) != 2 {
			return nil, fmt.Errorf("%s must be a key/value pair separated by a ':'", part)
		}
		k := strings.TrimSpace(kv[0])
		v := strings.TrimSpace(kv[1])

		if i == 0 {
			rtype, err := keyToRelationType(k)
			if err != nil {
				return nil, err
			}
			pred.Type = rtype
			pred.Label = v
		} else if strings.EqualFold(k, "prop") {
			prop, err := parseProperty(v)
			if err != nil {
				return nil, fmt.Errorf("invalid property: %v", err)
			}
			pred.Properties = append(pred.Properties, prop)
		} else if strings.EqualFold(k, "since") {
			since, err := time.Parse(time.DateOnly, v)
			if err != nil {
				return nil, err
			}
			pred.Since = since
		} else {
			pred.Attributes[k] = v
		}
	}

	return pred, nil
}

func keyToRelationType(key string) (oam.RelationType, error) {
	if key == "*" {
		return oam.RelationType("*"), nil
	}

	for _, rtype := range oam.RelationList {
		if strings.EqualFold(string(rtype), key) {
			return rtype, nil
		}
	}
	return "", fmt.Errorf("%s does not match any relation type", key)
}

func parseProperty(propstr string) (*Property, error) {
	parts := strings.Split(propstr, ",")
	prop := &Property{Attributes: make(map[string]string)}

	for i, part := range parts {
		kv := strings.Split(part, ":")
		if len(kv) != 2 {
			return nil, fmt.Errorf("%s must be a key/value pair separated by a ':'", part)
		}
		k := strings.TrimSpace(kv[0])
		v := strings.TrimSpace(kv[1])

		if i == 0 {
			ptype, err := keyToPropertyType(k)
			if err != nil {
				return nil, err
			}
			prop.Type = ptype
			prop.Name = v
		} else if strings.EqualFold(k, "since") {
			since, err := time.Parse(time.DateOnly, v)
			if err != nil {
				return nil, err
			}
			prop.Since = since
		} else {
			prop.Attributes[k] = v
		}
	}

	return prop, nil
}

func keyToPropertyType(key string) (oam.PropertyType, error) {
	for _, ptype := range oam.PropertyList {
		if strings.EqualFold(string(ptype), key) {
			return ptype, nil
		}
	}
	return "", fmt.Errorf("%s does not match any property type", key)
}
