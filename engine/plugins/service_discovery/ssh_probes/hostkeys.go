// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ssh_probes

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// hostKeyAlgorithms are offered one at a time, so a server's key of each
// common type is recorded and keys match whichever type another scan saw.
var hostKeyAlgorithms = []string{ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoRSASHA512}

const (
	dialTimeout      = 5 * time.Second
	handshakeTimeout = 10 * time.Second
	maxBanner        = 255
)

// errKeyCaptured ends the handshake once the host key is known. The client
// never reaches authentication, so no user name or credential is sent.
var errKeyCaptured = errors.New("host key captured")

type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// hostKeys connects to the SSH server at addr once per host key algorithm
// and returns its version banner and the distinct host keys it presented,
// each as "<key type> SHA256:<base64 fingerprint>".
func hostKeys(ctx context.Context, dial dialFunc, addr string) (string, []string, error) {
	var banner string
	var keys []string
	var lastErr error
	for _, algo := range hostKeyAlgorithms {
		if err := ctx.Err(); err != nil {
			return banner, keys, err
		}

		b, key, err := hostKey(ctx, dial, addr, algo)
		if b != "" && banner == "" {
			banner = b
		}
		if err != nil {
			lastErr = err
			continue
		}
		if key != "" && !contains(keys, key) {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 && lastErr != nil {
		return banner, nil, lastErr
	}

	return banner, keys, nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}

	return false
}

// hostKey runs one key exchange offering only algo and returns the banner
// and the presented host key.
func hostKey(ctx context.Context, dial dialFunc, addr, algo string) (string, string, error) {
	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	conn, err := dial(dctx, "tcp", addr)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	rec := &bannerConn{Conn: conn}
	var key string
	cfg := &ssh.ClientConfig{
		HostKeyAlgorithms: []string{algo},
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			key = k.Type() + " " + ssh.FingerprintSHA256(k)
			return errKeyCaptured
		},
		Timeout: handshakeTimeout,
	}

	_, _, _, err = ssh.NewClientConn(rec, addr, cfg)
	if key != "" {
		return rec.banner(), key, nil
	}
	if err == nil {
		err = errors.New("the server presented no host key")
	}

	return rec.banner(), "", err
}

// bannerConn records the server's identification line as it is read.
type bannerConn struct {
	net.Conn
	mu   sync.Mutex
	buf  bytes.Buffer
	done bool
}

func (c *bannerConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.done && n > 0 {
		c.buf.Write(p[:n])
		if bytes.Contains(c.buf.Bytes(), []byte("\n")) || c.buf.Len() > maxBanner {
			c.done = true
		}
	}

	return n, err
}

// banner returns the server's "SSH-2.0-..." identification, or "".
func (c *bannerConn) banner() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, line := range strings.Split(c.buf.String(), "\n") {
		if line = strings.TrimSpace(line); strings.HasPrefix(line, "SSH-") {
			if len(line) > maxBanner {
				line = line[:maxBanner]
			}

			return line
		}
	}

	return ""
}
