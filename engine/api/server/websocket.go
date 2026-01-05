// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

func (s *Server) wsLogsHandler(w http.ResponseWriter, r *http.Request) {
	sid := mux.Vars(r)["session_token"]

	// Check if the session token is valid
	token, err := uuid.Parse(sid)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid session token", err)
		return
	}
	// Check if the session exists
	// and if the session is not already terminated
	sess := s.mgr.GetSession(token)
	if sess == nil {
		writeError(w, http.StatusNotFound, "session not found", ErrNotFound)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("ws upgrade failed: %v", err)
		return
	}

	conn.SetReadLimit(1 << 20)
	_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	go writeLoop(conn, sess.PubSub().Subscribe())
	s.log.Info("connected to session log stream")
}

func writeLoop(conn *websocket.Conn, ch <-chan *string) {
	ping := time.NewTicker(30 * time.Second)
	defer ping.Stop()

	for {
		select {
		case msg, ok := <-ch:
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				_ = conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if err := conn.WriteJSON(*msg); err != nil {
				return
			}
		case <-ping.C:
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}
