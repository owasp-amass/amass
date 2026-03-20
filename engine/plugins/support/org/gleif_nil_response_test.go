// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/net/http"
	"github.com/stretchr/testify/require"
)

func TestGLEIFGetLEIRecordNilResponseNoPanic(t *testing.T) {
	t.Cleanup(func() {
		requestWebPage = http.RequestWebPage
	})

	requestWebPage = func(ctx context.Context, r *http.Request) (*http.Response, error) {
		return nil, nil
	}

	require.NotPanics(t, func() {
		record, err := GLEIFGetLEIRecord("ZXTILKJKG63JELOEG630")
		require.Error(t, err)
		require.Nil(t, record)
	})
}

func TestGLEIFGetDirectParentRecordNilResponseNoPanic(t *testing.T) {
	t.Cleanup(func() {
		requestWebPage = http.RequestWebPage
	})

	requestWebPage = func(ctx context.Context, r *http.Request) (*http.Response, error) {
		return nil, nil
	}

	require.NotPanics(t, func() {
		record, err := GLEIFGetDirectParentRecord("25490065U2GR0UPXFY63")
		require.Error(t, err)
		require.Nil(t, record)
	})
}

func TestGLEIFGetDirectChildrenRecordsNilResponseNoPanic(t *testing.T) {
	t.Cleanup(func() {
		requestWebPage = http.RequestWebPage
	})

	requestWebPage = func(ctx context.Context, r *http.Request) (*http.Response, error) {
		return nil, nil
	}

	require.NotPanics(t, func() {
		records, err := GLEIFGetDirectChildrenRecords("INR2EJN1ERAN0W5ZP974")
		require.Error(t, err)
		require.Nil(t, records)
	})
}
