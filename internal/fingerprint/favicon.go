// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package fingerprint

import (
	"encoding/base64"
	"math/bits"
	"strconv"
	"strings"
)

// FaviconHash returns a favicon's hash in the convention Shodan and most
// recon tools use: MurmurHash3 (x86, 32-bit, seed 0) of the icon's base64
// encoding with a newline after every 76 characters and at the end (as
// Python's base64.encodebytes writes it), as a signed decimal. It returns ""
// for an empty icon.
func FaviconHash(icon []byte) string {
	if len(icon) == 0 {
		return ""
	}

	enc := base64.StdEncoding.EncodeToString(icon)
	var b strings.Builder
	for len(enc) > 76 {
		b.WriteString(enc[:76])
		b.WriteByte('\n')
		enc = enc[76:]
	}

	b.WriteString(enc)
	b.WriteByte('\n')
	return strconv.FormatInt(int64(int32(murmur3(b.String(), 0))), 10)
}

// murmur3 is MurmurHash3's x86 32-bit variant.
func murmur3(data string, seed uint32) uint32 {
	const c1, c2 = 0xcc9e2d51, 0x1b873593
	h := seed
	n := len(data)
	for i := 0; i+4 <= n; i += 4 {
		k := uint32(data[i]) | uint32(data[i+1])<<8 | uint32(data[i+2])<<16 | uint32(data[i+3])<<24
		k *= c1
		k = bits.RotateLeft32(k, 15)
		k *= c2
		h ^= k
		h = bits.RotateLeft32(h, 13)
		h = h*5 + 0xe6546b64
	}

	var k uint32
	tail := data[n&^3:]
	switch len(tail) {
	case 3:
		k ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k ^= uint32(tail[0])
		k *= c1
		k = bits.RotateLeft32(k, 15)
		k *= c2
		h ^= k
	}

	h ^= uint32(n)
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}
