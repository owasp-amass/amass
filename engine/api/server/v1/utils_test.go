// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"testing"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
)

// A TLS certificate is identified by its issuer and serial together, so two
// self-signed certificates that share serial 1 but come from different issuers
// must be stored as distinct entities, and the same certificate must reuse its
// entity rather than create a new one. PutAsset stored certificates by serial
// alone before, which collapsed the first case.
func TestPutAssetCertificateIdentity(t *testing.T) {
	sess := plugintest.NewSession(t)
	v := &V1Handlers{dis: &plugintest.Dispatcher{}}
	ctx := context.Background()

	cert := func(serial, issuer string) *oamcert.TLSCertificate {
		return &oamcert.TLSCertificate{
			Version:           "3",
			SerialNumber:      serial,
			SubjectCommonName: "device.local",
			IssuerCommonName:  issuer,
			NotBefore:         "2026-01-01T00:00:00Z",
			NotAfter:          "2027-01-01T00:00:00Z",
		}
	}

	idA, err := v.PutAsset(ctx, sess, cert("1", "Device A Root"))
	if err != nil {
		t.Fatalf("storing certificate A: %v", err)
	}

	idB, err := v.PutAsset(ctx, sess, cert("1", "Device B Root"))
	if err != nil {
		t.Fatalf("storing certificate B: %v", err)
	}
	if idA == idB {
		t.Fatalf("two serial-1 certificates from different issuers collapsed into entity %s", idA)
	}

	idA2, err := v.PutAsset(ctx, sess, cert("1", "Device A Root"))
	if err != nil {
		t.Fatalf("restoring certificate A: %v", err)
	}
	if idA2 != idA {
		t.Errorf("the same certificate produced a new entity: %s then %s", idA, idA2)
	}
}
