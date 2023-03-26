// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scripting

import (
	"context"
	"errors"
	"os"
	"regexp"

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

func contextExpired(ctx context.Context) bool {
	if ctx == nil {
		return true
	}

	select {
	case <-ctx.Done():
		return true
	default:
	}
	return false
}

func extractContext(udata *lua.LUserData) (context.Context, error) {
	if udata == nil {
		return nil, errors.New("the Lua user data was nil")
	}

	val := udata.Value
	if val == lua.LNil {
		return nil, errors.New("the user data value was nil")
	}

	wrapper, ok := val.(*contextWrapper)
	if !ok {
		return nil, errors.New("the user data was not a script context wrapper")
	}

	ctx := wrapper.Ctx
	if contextExpired(ctx) {
		return nil, errors.New("context expired")
	}
	return ctx, nil
}

// Wrapper so that scripts can write messages to the Amass log.
func (s *Script) log(L *lua.LState) int {
	if _, err := extractContext(L.CheckUserData(1)); err == nil {
		if msg := L.CheckString(2); msg != "" {
			s.sys.Config().Log.Print(s.String() + ": " + msg)
		}
	}
	return 0
}

// Wrapper that exposes a simple regular expression matching function.
func (s *Script) find(L *lua.LState) int {
	tb := L.NewTable()
	str := L.CheckString(1)
	pattern := L.CheckString(2)

	if str != "" && pattern != "" {
		if re, err := regexp.Compile(pattern); err == nil {
			for _, name := range re.FindAllString(str, -1) {
				tb.Append(lua.LString(name))
			}
		}
	}

	if tb.Len() > 0 {
		L.Push(tb)
	} else {
		L.Push(lua.LNil)
	}
	return 1
}

// Wrapper that exposes a regular expression matching function that supports submatches.
func (s *Script) submatch(L *lua.LState) int {
	tb := L.NewTable()
	str := L.CheckString(1)
	pattern := L.CheckString(2)

	if str != "" && pattern != "" {
		if re, err := regexp.Compile(pattern); err == nil {
			for _, matches := range re.FindAllStringSubmatch(str, -1) {
				mtb := L.NewTable()

				for _, match := range matches {
					mtb.Append(lua.LString(match))
				}
				tb.Append(mtb)
			}
		}
	}
	if tb.Len() > 0 {
		L.Push(tb)
	} else {
		L.Push(lua.LNil)
	}
	return 1
}

// Wrapper that exposes a function that returns the modification date/time of a file.
func (s *Script) modDateTime(L *lua.LState) int {
	var seconds int64

	fpath := L.CheckString(1)
	if fi, err := os.Stat(fpath); err == nil {
		seconds = fi.ModTime().Unix()
	}

	L.Push(lua.LNumber(seconds))
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
