// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ssh_probes

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"
)

// sshServer starts a local SSH server with ed25519 and ECDSA host keys. It
// counts every authentication attempt, which must stay zero.
func sshServer(t *testing.T) (string, []string, *atomic.Int32) {
	t.Helper()

	var attempts atomic.Int32
	cfg := &ssh.ServerConfig{
		// AuthLogCallback sees every attempt, including the "none" method.
		AuthLogCallback: func(ssh.ConnMetadata, string, error) { attempts.Add(1) },
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			attempts.Add(1)
			return nil, errors.New("denied")
		},
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			attempts.Add(1)
			return nil, errors.New("denied")
		},
		KeyboardInteractiveCallback: func(ssh.ConnMetadata, ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			attempts.Add(1)
			return nil, errors.New("denied")
		},
	}

	var want []string
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []any{edKey, ecKey} {
		signer, err := ssh.NewSignerFromKey(k)
		if err != nil {
			t.Fatal(err)
		}

		cfg.AddHostKey(signer)
		want = append(want, signer.PublicKey().Type()+" "+ssh.FingerprintSHA256(signer.PublicKey()))
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}

			go func() {
				defer func() { _ = c.Close() }()
				_, _, _, _ = ssh.NewServerConn(c, cfg)
			}()
		}
	}()

	return ln.Addr().String(), want, &attempts
}

func plainDial(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func TestHostKeysWithoutAuthenticating(t *testing.T) {
	addr, want, attempts := sshServer(t)
	banner, keys, err := hostKeys(context.Background(), plainDial, addr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(banner, "SSH-2.0-") {
		t.Errorf("banner = %q", banner)
	}

	slices.Sort(keys)
	slices.Sort(want)
	if !slices.Equal(keys, want) {
		t.Errorf("keys = %v\nwant   %v", keys, want)
	}
	if n := attempts.Load(); n != 0 {
		t.Errorf("%d authentication attempts were made", n)
	}
}

func TestHostKeysReportsUnreachableServers(t *testing.T) {
	refuse := func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("refused") }
	if _, keys, err := hostKeys(context.Background(), refuse, "127.0.0.1:22"); err == nil || len(keys) != 0 {
		t.Errorf("keys %v, err %v from a refused connection", keys, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := hostKeys(ctx, plainDial, "127.0.0.1:22"); !errors.Is(err, context.Canceled) {
		t.Errorf("a canceled session probed anyway: %v", err)
	}
}
