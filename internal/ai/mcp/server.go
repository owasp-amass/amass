// SPDX-License-Identifier: Apache-2.0
// Package mcp implements a deliberately small MCP stdio JSON-RPC server.
// It exposes only read-only tools and avoids new runtime dependencies.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/owasp-amass/amass/v5/internal/ai"
)

type Server struct{ Runner ai.ToolRunner }
type incoming struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

func rpcResult(id json.RawMessage, result any) any {
	return map[string]any{"jsonrpc": "2.0", "id": id, "result": result}
}
func rpcError(id json.RawMessage, code int, reason string) any {
	return map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": reason}}
}
func (s Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	reader := bufio.NewScanner(in)
	reader.Buffer(make([]byte, 4096), 2<<20)
	writer := bufio.NewWriter(out)
	initialized := false
	for reader.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		var request incoming
		if err := json.Unmarshal(reader.Bytes(), &request); err != nil {
			if err := write(writer, rpcError(nil, -32700, "parse error")); err != nil {
				return err
			}
			continue
		}
		if request.JSONRPC != "2.0" || request.Method == "" {
			if err := write(writer, rpcError(request.ID, -32600, "invalid JSON-RPC request")); err != nil {
				return err
			}
			continue
		}
		// Notifications intentionally have no response.
		if len(request.ID) == 0 {
			if request.Method == "notifications/initialized" {
				initialized = true
			}
			continue
		}
		if !initialized && request.Method != "initialize" && request.Method != "ping" {
			if err := write(writer, rpcError(request.ID, -32000, "MCP not initialized")); err != nil {
				return err
			}
			continue
		}
		var reply any
		switch request.Method {
		case "initialize":
			initialized = false
			var p struct {
				ProtocolVersion string `json:"protocolVersion"`
			}
			_ = json.Unmarshal(request.Params, &p)
			version := p.ProtocolVersion
			if version != "2025-11-25" {
				version = "2025-11-25"
			}
			reply = rpcResult(request.ID, map[string]any{"protocolVersion": version,
				"serverInfo":   map[string]any{"name": "amass-ai", "version": "0.1.0"},
				"capabilities": map[string]any{"tools": map[string]any{"listChanged": false}}})
		case "ping":
			reply = rpcResult(request.ID, map[string]any{})
		case "tools/list":
			tools := []any{}
			for _, t := range ai.Specs() {
				tools = append(tools, map[string]any{"name": t.Name, "description": t.Description, "inputSchema": t.Parameters})
			}
			reply = rpcResult(request.ID, map[string]any{"tools": tools})
		case "tools/call":
			var p struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments"`
			}
			if err := json.Unmarshal(request.Params, &p); err != nil || p.Name == "" {
				reply = rpcError(request.ID, -32602, "invalid tool request")
				break
			}
			toolCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
			result, err := s.Runner.Run(toolCtx, p.Name, p.Arguments)
			cancel()
			if err != nil {
				reply = rpcResult(request.ID, map[string]any{"isError": true, "content": []any{map[string]any{"type": "text", "text": err.Error()}}})
			} else {
				reply = rpcResult(request.ID, map[string]any{"content": []any{map[string]any{"type": "text", "text": string(result)}}})
			}
		default:
			reply = rpcError(request.ID, -32601, fmt.Sprintf("unsupported method: %s", request.Method))
		}
		if err := write(writer, reply); err != nil {
			return err
		}
	}
	return reader.Err()
}
func write(w *bufio.Writer, response any) error {
	data, err := json.Marshal(response)
	if err != nil {
		return err
	}
	if _, err = w.Write(append(data, '\n')); err != nil {
		return err
	}
	return w.Flush()
}
