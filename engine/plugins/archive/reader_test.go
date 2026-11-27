// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"context"

	et "github.com/owasp-amass/amass/v5/engine/types"
)

// inline does an archive's work at once, so a test sees its results when
// check returns.
type inline struct{}

func (inline) Enqueue(sess et.Session, _, _, _ string, work func(context.Context)) {
	work(sess.Ctx())
}
