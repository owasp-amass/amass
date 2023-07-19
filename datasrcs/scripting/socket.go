// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scripting

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"

	amassnet "github.com/owasp-amass/amass/v4/net"
	lua "github.com/yuin/gopher-lua"
)

const luaSocketTypeName = "socket"

type socketWrapper struct {
	Conn net.Conn
}

var connectMethods = map[string]lua.LGFunction{
	"close":    connectClose,
	"recv":     connectRecv,
	"recv_all": connectRecvAll,
	"send":     connectSend,
}

func registerSocketType(L *lua.LState) {
	mt := L.NewTypeMetatable(luaSocketTypeName)

	L.SetGlobal(luaSocketTypeName, mt)
	L.SetField(mt, "connect", L.NewFunction(connect))
	L.SetField(mt, "__index", L.SetFuncs(L.NewTable(), connectMethods))
}

// Wrapper so that scripts can make DNS queries.
func connect(L *lua.LState) int {
	ctx, err := extractContext(L.CheckUserData(1))
	host := L.CheckString(2)
	port := int(L.CheckNumber(3))
	proto := L.CheckString(4)
	if err != nil || host == "" || port <= 0 || proto == "" {
		L.Push(lua.LNil)
		L.Push(lua.LString("Proper parameters were not provided"))
		return 2
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := amassnet.DialContext(ctx, proto, addr)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(fmt.Sprintf("Failed to establish the connection: %v", err)))
		return 2
	}

	ud := L.NewUserData()
	ud.Value = &socketWrapper{Conn: conn}
	L.SetMetatable(ud, L.GetTypeMetatable(luaSocketTypeName))

	L.Push(ud)
	L.Push(lua.LNil)
	return 2
}

func connectRecv(L *lua.LState) int {
	s, err := extractSocket(L.CheckUserData(1))
	num := int(L.CheckNumber(2))
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString("Proper parameters were not provided"))
		return 2
	}

	buf := make([]byte, num*10)
	n, err := io.ReadAtLeast(s.Conn, buf, num)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(fmt.Sprintf("Error reading data from the connection: %v", err)))
		return 2
	}

	L.Push(lua.LString(string(buf[:n])))
	L.Push(lua.LNil)
	return 2
}

func connectRecvAll(L *lua.LState) int {
	s, err := extractSocket(L.CheckUserData(1))
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString("Proper parameters were not provided"))
		return 2
	}

	data, err := io.ReadAll(s.Conn)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(fmt.Sprintf("Error reading data from the connection: %v", err)))
		return 2
	}

	L.Push(lua.LString(string(data)))
	L.Push(lua.LNil)
	return 2
}

func connectSend(L *lua.LState) int {
	s, err := extractSocket(L.CheckUserData(1))
	data := L.CheckString(2)
	if err != nil || data == "" {
		L.Push(lua.LNumber(0))
		L.Push(lua.LString("Proper parameters were not provided"))
		return 2
	}

	n, err := io.WriteString(s.Conn, data)
	if err != nil || n == 0 {
		L.Push(lua.LNumber(n))
		L.Push(lua.LString(fmt.Sprintf("Error writing data on the connection: %v", err)))
		return 2
	}

	L.Push(lua.LNumber(n))
	L.Push(lua.LNil)
	return 2
}

func connectClose(L *lua.LState) int {
	if s, err := extractSocket(L.CheckUserData(1)); err == nil {
		s.Conn.Close()
	}
	return 0
}

func extractSocket(udata *lua.LUserData) (*socketWrapper, error) {
	if udata == nil {
		return nil, errors.New("the Lua user data was nil")
	}

	val := udata.Value
	if val == lua.LNil {
		return nil, errors.New("the user data value was nil")
	}

	wrapper, ok := val.(*socketWrapper)
	if !ok {
		return nil, errors.New("the user data was not a script sock wrapper")
	}
	return wrapper, nil
}
