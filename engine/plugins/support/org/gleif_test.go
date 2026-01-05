// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetLEIRecord(t *testing.T) {
	record, err := GLEIFGetLEIRecord("ZXTILKJKG63JELOEG630")
	assert.NoError(t, err)
	assert.NotNil(t, record)
	assert.Equal(t, "AMAZON.COM, INC.", record.Attributes.Entity.LegalName.Name)
}

func TestGetDirectParentRecord(t *testing.T) {
	record, err := GLEIFGetDirectParentRecord("25490065U2GR0UPXFY63")
	assert.NoError(t, err)
	assert.NotNil(t, record)
	assert.Equal(t, "AMAZON.COM, INC.", record.Attributes.Entity.LegalName.Name)
}

func TestGetDirectChildrenRecord(t *testing.T) {
	children, err := GLEIFGetDirectChildrenRecords("INR2EJN1ERAN0W5ZP974")
	assert.NoError(t, err)
	assert.NotEmpty(t, children)
	assert.GreaterOrEqual(t, len(children), 11)
}
