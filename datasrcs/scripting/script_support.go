// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package scripting

import (
	"context"
	"errors"
	"regexp"

	"github.com/OWASP/Amass/v3/requests"
	"github.com/caffix/eventbus"
	lua "github.com/yuin/gopher-lua"
)

type contextWrapper struct {
	Ctx context.Context
}

// Converts Go Context to Lua UserData.
func (s *Script) contextToUserData(ctx context.Context) *lua.LUserData {
	L := s.luaState
	ud := L.NewUserData()

	ud.Value = &contextWrapper{Ctx: ctx}
	L.SetMetatable(ud, L.GetTypeMetatable("context"))
	return ud
}

func checkContextExpired(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return errors.New("Context expired")
	default:
	}

	return nil
}

func extractContext(udata *lua.LUserData) (context.Context, error) {
	if udata == nil {
		return nil, errors.New("Lua user data was nil")
	}

	val := udata.Value
	if val == nil {
		return nil, errors.New("The user data value was nil")
	}

	wrapper, ok := val.(*contextWrapper)
	if !ok {
		return nil, errors.New("The user data was not a script context wrapper")
	}

	ctx := wrapper.Ctx
	if err := checkContextExpired(ctx); err != nil {
		return nil, err
	}

	return ctx, nil
}

// Wrapper so that scripts can write messages to the Amass log.
func (s *Script) log(L *lua.LState) int {
	ctx, err := extractContext(L.CheckUserData(1))
	if err != nil {
		return 0
	}

	_, bus, err := requests.ContextConfigBus(ctx)
	if err != nil {
		return 0
	}

	lv := L.Get(2)
	if lv == nil {
		return 0
	}

	if msg, ok := lv.(lua.LString); ok {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, s.String()+": "+string(msg))
	}
	return 0
}

// Wrapper that exposes a simple regular expression matching function.
func (s *Script) find(L *lua.LState) int {
	lv := L.Get(1)
	if lv == nil {
		L.Push(lua.LNil)
		return 1
	}

	str, ok := lv.(lua.LString)
	if !ok {
		L.Push(lua.LNil)
		return 1
	}

	lv = L.Get(2)
	if lv == nil {
		L.Push(lua.LNil)
		return 1
	}

	pattern, ok := lv.(lua.LString)
	if !ok {
		L.Push(lua.LNil)
		return 1
	}

	re, err := regexp.Compile(string(pattern))
	if err != nil {
		L.Push(lua.LNil)
		return 1
	}

	tb := L.NewTable()
	for _, name := range re.FindAllString(string(str), -1) {
		tb.Append(lua.LString(name))
	}

	L.Push(tb)
	return 1
}

// Wrapper that exposes a regular expression matching function that supports submatches.
func (s *Script) submatch(L *lua.LState) int {
	lv := L.Get(1)
	if lv == nil {
		L.Push(lua.LNil)
		return 1
	}

	str, ok := lv.(lua.LString)
	if !ok {
		L.Push(lua.LNil)
		return 1
	}

	lv = L.Get(2)
	if lv == nil {
		L.Push(lua.LNil)
		return 1
	}

	pattern, ok := lv.(lua.LString)
	if !ok {
		L.Push(lua.LNil)
		return 1
	}

	re, err := regexp.Compile(string(pattern))
	if err != nil {
		L.Push(lua.LNil)
		return 1
	}

	matches := re.FindAllStringSubmatch(string(str), -1)
	if matches == nil {
		L.Push(lua.LNil)
		return 1
	}

	tb := L.NewTable()
	for _, match := range matches {
		if len(match) > 1 {
			tb.Append(lua.LString(match[1]))
		}
	}

	L.Push(tb)
	return 1
}

func getStringField(L *lua.LState, t lua.LValue, key string) (string, bool) {
	if lv := L.GetField(t, key); lv != nil {
		if s, ok := lv.(lua.LString); ok {
			return string(s), true
		}
	}
	return "", false
}

func getNumberField(L *lua.LState, t lua.LValue, key string) (float64, bool) {
	if lv := L.GetField(t, key); lv != nil {
		if n, ok := lv.(lua.LNumber); ok {
			return float64(n), true
		}
	}
	return 0, false
}
