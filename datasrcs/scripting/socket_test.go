// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scripting

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v4/requests"
)

func TestSocketRecv(t *testing.T) {
	script, sys := setupMockScriptEnv(`
		name="recv"
		type="testing"

		function vertical(ctx, domain)
			local conn, err = socket.connect(ctx, "127.0.0.1", 8080, "tcp")
			if (err ~= nil and err ~= "") then
				log(ctx, err)
				return
			end

			local data
			data, err = conn:recv(15)
			if (err == nil and data == "Hello unit test") then
				new_name(ctx, "yes.owasp.org")
			end
			conn:close()
		end
	`)
	if script == nil || sys == nil {
		t.Fatal("failed to initialize the scripting environment")
	}
	defer func() { _ = sys.Shutdown() }()

	ln, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		t.Fatal("failed to listen on port 8080")
	}
	defer ln.Close()

	go func(ln net.Listener) {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		_, _ = io.WriteString(conn, "Hello unit test")
	}(ln)

	sys.Config().AddDomain("owasp.org")
	script.Input() <- &requests.DNSRequest{Domain: "owasp.org"}

	timer := time.NewTimer(time.Duration(15) * time.Second)
	defer timer.Stop()

	select {
	case <-timer.C:
		t.Error("the test timed out")
	case msg := <-script.Output():
		if ans, ok := msg.(*requests.DNSRequest); !ok || ans.Name != "yes.owasp.org" {
			t.Error("Failed")
		}
	}
}

func TestSocketRecvAll(t *testing.T) {
	script, sys := setupMockScriptEnv(`
		name="recv_all"
		type="testing"

		function vertical(ctx, domain)
			local conn, err = socket.connect(ctx, "127.0.0.1", 8080, "tcp")
			if (err ~= nil and err ~= "") then
				log(ctx, err)
				return
			end

			local data
			data, err = conn:recv_all()
			if (err == nil and data == "Hello unit test") then
				new_name(ctx, "yes.owasp.org")
			end
			conn:close()
		end
	`)
	if script == nil || sys == nil {
		t.Fatal("failed to initialize the scripting environment")
	}
	defer func() { _ = sys.Shutdown() }()

	ln, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		t.Fatal("failed to listen on port 8080")
	}
	defer ln.Close()

	go func(ln net.Listener) {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		_, _ = io.WriteString(conn, "Hello unit test")
	}(ln)

	sys.Config().AddDomain("owasp.org")
	script.Input() <- &requests.DNSRequest{Domain: "owasp.org"}

	timer := time.NewTimer(time.Duration(15) * time.Second)
	defer timer.Stop()

	select {
	case <-timer.C:
		t.Error("the test timed out")
	case msg := <-script.Output():
		if ans, ok := msg.(*requests.DNSRequest); !ok || ans.Name != "yes.owasp.org" {
			t.Error("Failed")
		}
	}
}

func TestSocketSend(t *testing.T) {
	expected := "Hello unit test"
	script, sys := setupMockScriptEnv(`
		name="send"
		type="testing"

		function vertical(ctx, domain)
			local conn, err = socket.connect(ctx, "127.0.0.1", 8080, "tcp")
			if (err ~= nil and err ~= "") then
				log(ctx, err)
			end

			conn:send("Hello unit test")
		end
	`)
	if script == nil || sys == nil {
		t.Fatal("failed to initialize the scripting environment")
	}
	defer func() { _ = sys.Shutdown() }()

	ln, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		t.Fatal("failed to listen on port 8080")
	}
	defer ln.Close()

	datach := make(chan string)
	go func(ln net.Listener, ch chan string) {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		var str string
		buf := make([]byte, 64)
		if n, err := conn.Read(buf); err == nil {
			str = string(buf[:n])
		}
		ch <- str
	}(ln, datach)

	sys.Config().AddDomain("owasp.org")
	script.Input() <- &requests.DNSRequest{Domain: "owasp.org"}

	timer := time.NewTimer(time.Duration(15) * time.Second)
	defer timer.Stop()

	select {
	case <-timer.C:
		t.Error("the test timed out")
	case data := <-datach:
		if data != expected {
			t.Error(data)
		}
	}
}
