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
	Subject   string
	Predicate string
	Object    string
}

type Node struct {
	Key        string
	Type       oam.AssetType
	Since      time.Time
	Attributes map[string]string
	Properties []Property
}

type Predicate struct {
	Label      string
	Type       oam.RelationType
	Since      time.Time
	Attributes map[string]string
	Properties []Property
}

type Property struct {
	Name       string
	Value      string
	Since      time.Time
	Type       oam.PropertyType
	Attributes map[string]string
}

func ParseTriple(triple string) (*Triple, error) {
	tristrs, direction, err := splitTriple(triple)
	if err != nil {
		return nil, fmt.Errorf("invalid triple format: %w", err)
	}

	return &Triple{
		Direction: direction,
		Subject:   parts[0],
		Predicate: parts[1],
		Object:    parts[2],
	}, nil
}

func splitTriple(triple string) ([]string, int, error) {
	start := 0
	var tstrs []string
	direction := DirectionOutgoing

	for i := 0; i < 3; i++ {
		substr := triple[start:]

		sidx := strings.Index(substr, "<")
		if sidx == -1 {
			return nil, direction, fmt.Errorf("triple must contain an opening angle bracket for the %s", tripleFields[i])
		}
		sidx += 1 // Move past the opening angle bracket

		eidx := strings.Index(substr, ">")
		if eidx == -1 {
			return nil, direction, fmt.Errorf("triple must contain a closing angle bracket for the %s", tripleFields[i])
		}
		if eidx <= sidx {
			return nil, direction, fmt.Errorf("the %s must contain a closing angle bracket after an opening angle bracket", tripleFields[i])
		}
		tstrs = append(tstrs, strings.TrimSpace(triple[sidx:eidx]))

		start += eidx + 1 // Move past the closing angle bracket
		substr = triple[start:]
		if i == 0 {
			if idx := strings.Index(substr, "<-"); idx != -1 && (idx == 0 || idx == 1) {
				direction = DirectionIncoming
				start += 2 // Move past the "<-"
			} else if idx := strings.Index(substr, "-"); idx != -1 && (idx == 0 || idx == 1) {
				start += 1 // Move past the "-"
			} else {
				return nil, direction, fmt.Errorf("triple must contain a hyphen or '<-' after the subject")
			}
		} else if i == 1 {
			if idx := strings.Index(substr, "->"); idx != -1 && (idx == 0 || idx == 1) {
				if direction == DirectionIncoming {
					return nil, direction, fmt.Errorf("triple cannot have both '<-' and '->'")
				}
				start += 2 // Move past the "<-"
			} else if idx := strings.Index(substr, "-"); idx != -1 && (idx == 0 || idx == 1) {
				if direction == DirectionOutgoing {
					return nil, direction, fmt.Errorf("triple must have a direction specified with '<-' or '->'")
				}
				start += 1 // Move past the "-"
			} else {
				return nil, direction, fmt.Errorf("triple must contain a hyphen or '<-' after the predicate")
			}
		}
	}

	return tstrs, direction, nil
}
