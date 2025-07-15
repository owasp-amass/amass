// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package gleif

import (
	"fmt"
	"testing"

	"github.com/owasp-amass/open-asset-model/general"
	"github.com/stretchr/testify/assert"
)

func TestGetLEIRecord(t *testing.T) {
	p := NewGLEIF()
	g := p.(*gleif)

	lei := "ZXTILKJKG63JELOEG630"
	id := &general.Identifier{
		UniqueID: fmt.Sprintf("%s:%s", general.LEICode, lei),
		ID:       lei,
		Type:     general.LEICode,
	}

	record, err := g.getLEIRecord(id)
	assert.NoError(t, err)
	assert.NotNil(t, record)
	assert.Equal(t, "AMAZON.COM, INC.", record.Attributes.Entity.LegalName.Name)
}

func TestGetDirectParentRecord(t *testing.T) {
	p := NewGLEIF()
	g := p.(*gleif)

	lei := "25490065U2GR0UPXFY63"
	id := &general.Identifier{
		UniqueID: fmt.Sprintf("%s:%s", general.LEICode, lei),
		ID:       lei,
		Type:     general.LEICode,
	}

	record, err := g.getDirectParentRecord(id)
	assert.NoError(t, err)
	assert.NotNil(t, record)
	assert.Equal(t, "AMAZON.COM, INC.", record.Attributes.Entity.LegalName.Name)
}

func TestGetDirectChildrenRecord(t *testing.T) {
	p := NewGLEIF()
	g := p.(*gleif)

	lei := "INR2EJN1ERAN0W5ZP974"
	id := &general.Identifier{
		UniqueID: fmt.Sprintf("%s:%s", general.LEICode, lei),
		ID:       lei,
		Type:     general.LEICode,
	}

	children, err := g.getDirectChildrenRecords(id)
	assert.NoError(t, err)
	assert.NotEmpty(t, children)
	assert.GreaterOrEqual(t, len(children), 11)
}
