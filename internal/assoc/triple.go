// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package assoc

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	oam "github.com/owasp-amass/open-asset-model"
)

const (
	DirectionIncoming = iota
	DirectionOutgoing
	DirectionUnknown
)

type Triple struct {
	Direction int // 0 for incoming, 1 for outgoing
	Subject   *Node
	Predicate *Predicate
	Object    *Node
}

type Node struct {
	Key        string
	Regexp     *regexp.Regexp
	Type       oam.AssetType
	Since      time.Time
	Attributes map[string]*AttrValue
	Properties []*Property
}

type Predicate struct {
	Label      string
	Regexp     *regexp.Regexp
	Type       oam.RelationType
	Since      time.Time
	Attributes map[string]*AttrValue
	Properties []*Property
}

type Property struct {
	Name       string
	Regexp     *regexp.Regexp
	Since      time.Time
	Type       oam.PropertyType
	Attributes map[string]*AttrValue
}

type AttrValue struct {
	Value  string
	Regexp *regexp.Regexp
}

func ParseTriple(triple string) (*Triple, error) {
	elements, direction, err := splitTriple(triple)
	if err != nil {
		return nil, fmt.Errorf("invalid triple format: %v", err)
	}

	subject, err := parseNode(elements[0])
	if err != nil {
		return nil, fmt.Errorf("invalid subject: %v", err)
	}

	predicate, err := parsePredicate(elements[1])
	if err != nil {
		return nil, fmt.Errorf("invalid predicate: %v", err)
	}

	object, err := parseNode(elements[2])
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

func splitTriple(s string) ([]string, int, error) {
	var elements []string
	direction := DirectionUnknown

	var currentPart strings.Builder
	var inAngle, inSquare, inRegex bool
	var atHyphen, atPound, atSlash, atOpeningAngle bool
	for _, r := range s {
		switch r {
		case '<':
			if !inAngle {
				atOpeningAngle = true
			}
			atPound = false
			atSlash = false
			atHyphen = false
			currentPart.WriteRune(r)
		case '>':
			if inAngle && !inRegex {
				inAngle = false
				currentPart.WriteRune(r)
				elements = append(elements, strings.TrimSpace(currentPart.String()))
				currentPart.Reset()
			} else if atHyphen && !inAngle && direction == DirectionUnknown && len(elements) == 2 {
				direction = DirectionOutgoing
			} else {
				return nil, direction, fmt.Errorf("unexpected closing angle bracket '>'")
			}
			atPound = false
			atSlash = false
			atHyphen = false
			atOpeningAngle = false
		case '-':
			if atOpeningAngle {
				if direction == DirectionUnknown && len(elements) == 1 {
					direction = DirectionIncoming
					tmpstr := currentPart.String()
					currentPart.Reset()
					currentPart.WriteString(tmpstr[:len(tmpstr)-1]) // Remove the trailing '<'
				} else {
					return nil, direction, fmt.Errorf("unexpected hyphen '-' after opening angle bracket '<'")
				}
				inAngle = false
			} else if !inAngle && direction == DirectionUnknown && len(elements) == 1 {
				atHyphen = true
			} else if !inAngle && len(elements) == 2 {
				atHyphen = true
			} else {
				currentPart.WriteRune(r)
			}
			atPound = false
			atSlash = false
			atOpeningAngle = false
		case '[':
			if inAngle && !inRegex {
				inSquare = true
			}
			atPound = false
			atSlash = false
			atHyphen = false
			atOpeningAngle = false
			currentPart.WriteRune(r)
		case ']':
			if inSquare && !inRegex {
				inSquare = false
			}
			atPound = false
			atSlash = false
			atHyphen = false
			atOpeningAngle = false
			currentPart.WriteRune(r)
		case '#':
			if inRegex && atSlash {
				inRegex = false
			}
			atPound = true
			atSlash = false
			atHyphen = false
			atOpeningAngle = false
			currentPart.WriteRune(r)
		case '/':
			if inAngle && atPound {
				inRegex = true
			}
			atSlash = true
			atPound = false
			atHyphen = false
			atOpeningAngle = false
			currentPart.WriteRune(r)
		default:
			if atOpeningAngle {
				inAngle = true
			}
			atPound = false
			atSlash = false
			atHyphen = false
			atOpeningAngle = false
			currentPart.WriteRune(r)
		}
	}

	if inAngle {
		return nil, direction, fmt.Errorf("unclosed angle bracket '<'")
	}
	if direction == DirectionUnknown {
		return nil, direction, fmt.Errorf("triple must contain a direction specified with '<-' or '->'")
	}
	if len(elements) != 3 {
		return nil, direction, fmt.Errorf("triple must contain exactly three elements")
	}
	return elements, direction, nil
}

func splitElement(estr string) []string {
	var parts []string

	var atPound, atSlash bool
	var inBracket, inRegex bool
	var currentPart strings.Builder
	for _, r := range estr {
		switch r {
		case '[':
			if !inRegex {
				inBracket = true
			}
			currentPart.WriteRune(r)
		case ']':
			if inBracket && !inRegex {
				inBracket = false
			}
			currentPart.WriteRune(r)
		case ',':
			if inBracket || inRegex {
				currentPart.WriteRune(r)
			} else {
				parts = append(parts, strings.TrimSpace(currentPart.String()))
				currentPart.Reset()
			}
		case '#':
			if inRegex && atSlash {
				inRegex = false
			}
			atPound = true
			atSlash = false
			currentPart.WriteRune(r)
		case '/':
			if atPound {
				inRegex = true
			}
			atSlash = true
			atPound = false
			currentPart.WriteRune(r)
		default:
			currentPart.WriteRune(r)
		}
	}

	return append(parts, strings.TrimSpace(currentPart.String())) // Add the last part
}

func parseNode(nodestr string) (*Node, error) {
	if !strings.HasPrefix(nodestr, "<") || !strings.HasSuffix(nodestr, ">") {
		return nil, fmt.Errorf("node must be enclosed in angle brackets, e.g., <type:asset_key>")
	}
	nodestr = strings.Trim(nodestr, "<>")

	if p := strings.TrimSpace(nodestr); p == "*" {
		return &Node{
			Key:        "*",
			Type:       oam.AssetType("*"),
			Attributes: make(map[string]*AttrValue),
		}, nil
	}

	node := &Node{Attributes: make(map[string]*AttrValue)}
	for i, part := range splitElement(nodestr) {
		if i == 0 && strings.TrimSpace(part) == "*" {
			node.Key = "*"
			node.Type = oam.AssetType("*")
			continue
		}

		kv := strings.SplitN(part, ":", 2)
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
			if restr, yes := isRegexp(v); yes {
				if re, err := regexp.Compile(restr); err != nil {
					return nil, fmt.Errorf("invalid regular expression for asset key: %v", err)
				} else {
					node.Regexp = re
				}
			}
		} else if strings.EqualFold(k, "prop") {
			prop, err := parseProperty(v)
			if err != nil {
				return nil, fmt.Errorf("invalid property - %s: %v", v, err)
			}
			node.Properties = append(node.Properties, prop)
		} else if strings.EqualFold(k, "since") {
			since, err := time.Parse(time.DateOnly, v)
			if err != nil {
				return nil, err
			}
			node.Since = since
		} else {
			av := &AttrValue{Value: v}
			if restr, yes := isRegexp(v); yes {
				if re, err := regexp.Compile(restr); err != nil {
					return nil, fmt.Errorf("invalid regular expression for asset attribute: %v", err)
				} else {
					av.Regexp = re
				}
			}
			node.Attributes[k] = av
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
	if !strings.HasPrefix(predstr, "<") || !strings.HasSuffix(predstr, ">") {
		return nil, fmt.Errorf("predicate must be enclosed in angle brackets, e.g., <type:relation_label>")
	}
	predstr = strings.Trim(predstr, "<>")

	if p := strings.TrimSpace(predstr); p == "*" {
		return &Predicate{
			Label:      "*",
			Type:       oam.RelationType("*"),
			Attributes: make(map[string]*AttrValue),
		}, nil
	}

	pred := &Predicate{Attributes: make(map[string]*AttrValue)}
	for i, part := range splitElement(predstr) {
		if i == 0 && strings.TrimSpace(part) == "*" {
			pred.Label = "*"
			pred.Type = oam.RelationType("*")
			continue
		}

		kv := strings.SplitN(part, ":", 2)
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
			if restr, yes := isRegexp(v); yes {
				if re, err := regexp.Compile(restr); err != nil {
					return nil, fmt.Errorf("invalid regular expression for relation label: %v", err)
				} else {
					pred.Regexp = re
				}
			}
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
			av := &AttrValue{Value: v}
			if restr, yes := isRegexp(v); yes {
				if re, err := regexp.Compile(restr); err != nil {
					return nil, fmt.Errorf("invalid regular expression for relation attribute: %v", err)
				} else {
					av.Regexp = re
				}
			}
			pred.Attributes[k] = av
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
	if !strings.HasPrefix(propstr, "[") || !strings.HasSuffix(propstr, "]") {
		return nil, fmt.Errorf("property must be enclosed in square brackets, e.g., [type:property_name]")
	}

	propstr = strings.Trim(propstr, "[]")
	parts := strings.Split(propstr, ",")
	prop := &Property{Attributes: make(map[string]*AttrValue)}

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
			if restr, yes := isRegexp(v); yes {
				if re, err := regexp.Compile(restr); err != nil {
					return nil, fmt.Errorf("invalid regular expression for property name: %v", err)
				} else {
					prop.Regexp = re
				}
			}
		} else if strings.EqualFold(k, "since") {
			since, err := time.Parse(time.DateOnly, v)
			if err != nil {
				return nil, err
			}
			prop.Since = since
		} else {
			av := &AttrValue{Value: v}
			if restr, yes := isRegexp(v); yes {
				if re, err := regexp.Compile(restr); err != nil {
					return nil, fmt.Errorf("invalid regular expression for property attribute: %v", err)
				} else {
					av.Regexp = re
				}
			}
			prop.Attributes[k] = av
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
