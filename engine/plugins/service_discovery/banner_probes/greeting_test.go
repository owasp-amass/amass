// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package banner_probes

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestCatalog(t *testing.T) {
	c, err := loadCatalog()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.probedPorts()) == 0 {
		t.Fatal("no ports are probed")
	}
	for _, port := range c.probedPorts() {
		if port == 22 {
			t.Error("port 22 belongs to the SSH probe")
		}
	}

	dup := catalog{Protocols: []protocol{{ServiceType: "a", Ports: []int{25}, Greeting: "x", Source: "https://a"},
		{ServiceType: "b", Ports: []int{25}, Greeting: "y", Source: "https://b"}}}
	if err := dup.validate(); err == nil {
		t.Error("a port listed for two protocols was accepted")
	}
}

func TestClassify(t *testing.T) {
	c, err := loadCatalog()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		port int
		line string
		want string
	}{
		{25, "220 mx.example.com ESMTP Postfix", "smtp"},
		{587, "220-mail.example.com Microsoft ESMTP MAIL service ready", "smtp"},
		{21, "220 (vsFTPd 3.0.5)", "ftp"},
		{110, "+OK Dovecot ready.", "pop3"},
		{143, "* OK [CAPABILITY IMAP4rev1] Dovecot ready.", "imap"},
		{993, "* OK [CAPABILITY IMAP4rev1] Dovecot ready.", "imap"},
		{465, "220 mx.example.com ESMTP Postfix", "smtp"},
		// A greeting is read only as the protocol its port is listed for.
		{110, "220 mx.example.com ESMTP", ""},
		{25, "HTTP/1.1 400 Bad Request", ""},
	} {
		p, ok := c.classify(tc.port, tc.line)
		if got := p.ServiceType; ok != (tc.want != "") || got != tc.want {
			t.Errorf("classify(%d, %q) = %q, want %q", tc.port, tc.line, got, tc.want)
		}
	}
}

func listen(t *testing.T, serve func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				serve(conn)
			}()
		}
	}()
	return ln.Addr().String()
}

func TestReadGreeting(t *testing.T) {
	var d net.Dialer
	addr := listen(t, func(c net.Conn) {
		_, _ = c.Write([]byte("220 mx.example.com ESMTP Exim 4.97 Sat, 14 Nov 2026 00:00:00 +0000\r\n"))
		// The probe must never write: anything it sends fails the test.
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		if n, _ := c.Read(make([]byte, 1)); n > 0 {
			t.Error("the probe sent data to the server")
		}
	})

	line, _, err := readGreeting(context.Background(), d.DialContext, addr, false, 0)
	if err != nil || line != "220 mx.example.com ESMTP Exim 4.97 Sat, 14 Nov 2026 00:00:00 +0000" {
		t.Errorf("greeting %q, %v", line, err)
	}
}

func TestReadGreetingFromSilentServer(t *testing.T) {
	var d net.Dialer
	addr := listen(t, func(c net.Conn) {
		time.Sleep(readTimeout + time.Second)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*readTimeout)
	defer cancel()
	if _, _, err := readGreeting(ctx, d.DialContext, addr, false, 0); !errors.Is(err, errNoGreeting) {
		t.Errorf("silent server: %v, want errNoGreeting", err)
	}
}

// On an implicit TLS port the probe completes the handshake, records the
// certificate presented (self-signed here, so never verified) and reads the
// greeting inside the tunnel.
func TestReadGreetingOverTLS(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(993), Subject: pkix.Name{CommonName: "imap.example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}

	var d net.Dialer
	addr := listen(t, func(c net.Conn) {
		tc := tls.Server(c, cfg)
		if err := tc.Handshake(); err != nil {
			return
		}
		_, _ = tc.Write([]byte("* OK [CAPABILITY IMAP4rev1] Dovecot ready.\r\n"))
		_ = tc.SetReadDeadline(time.Now().Add(time.Second))
		if n, _ := tc.Read(make([]byte, 1)); n > 0 {
			t.Error("the probe sent data inside the tunnel")
		}
	})

	line, certs, err := readGreeting(context.Background(), d.DialContext, addr, true, 0)
	if err != nil || line != "* OK [CAPABILITY IMAP4rev1] Dovecot ready." {
		t.Fatalf("greeting %q, %v", line, err)
	}
	if len(certs) != 1 || certs[0].Subject.CommonName != "imap.example.com" {
		t.Errorf("certificates = %v", certs)
	}
}
