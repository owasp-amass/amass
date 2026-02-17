// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/owasp-amass/amass/v5/config"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
)

const MaxBulkItems = 5000

type Client struct {
	base       string
	httpClient http.Client
	wsClient   *websocket.Conn
	done       chan struct{}
}

type CreateSessionResponse struct {
	SessionToken string `json:"sessionToken"`
}

type ListSessionsResponse struct {
	SessionTokens []string `json:"sessionTokens"`
}

type AddAssetResponse struct {
	EntityID string `json:"entityID"`
}

// Bulk typed add: {"items":[ <OAM obj>, <OAM obj>, ... ]}
// where each item is arbitrary JSON object without "type".
type BulkAddAssetsRequest struct {
	Items []json.RawMessage `json:"items"`
}

type BulkAddAssetsResponse struct {
	Ingested int64 `json:"ingested"`
	Stored   int64 `json:"stored"`
	Failed   int64 `json:"failed"`
}

// NewClient returns a pointer to a Client struct for the specified server URL.
func NewClient(url string) *Client {
	return &Client{
		base:       url,
		httpClient: http.Client{},
		done:       make(chan struct{}),
	}
}

// Close terminates any open connections associated with the client.
func (c *Client) Close() {
	close(c.done)
}

// Creates a new session on the server with the provided configuration.
func (c *Client) CreateSession(config *config.Config) (uuid.UUID, error) {
	raw, err := json.Marshal(config)
	if err != nil {
		return uuid.UUID{}, err
	}

	req, _ := http.NewRequest(http.MethodPost, c.base+"/v1/sessions", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return uuid.UUID{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		msg, err := readJSONError(resp)
		if err != nil {
			return uuid.UUID{}, fmt.Errorf("createSession: status=%s", resp.Status)
		}
		return uuid.UUID{}, fmt.Errorf("createSession: status=%s error=%s", resp.Status, msg)
	}

	var out CreateSessionResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return uuid.UUID{}, err
	}

	return uuid.Parse(out.SessionToken)
}

// Lists the active session and associated tokens on the server.
func (c *Client) ListSessions() ([]uuid.UUID, error) {
	req, _ := http.NewRequest(http.MethodGet, c.base+"/v1/sessions", nil)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		msg, err := readJSONError(resp)
		if err != nil {
			return nil, fmt.Errorf("listSessions: status=%s", resp.Status)
		}
		return nil, fmt.Errorf("listSessions: status=%s error=%s", resp.Status, msg)
	}

	var out ListSessionsResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}

	tokens := make([]uuid.UUID, 0, len(out.SessionTokens))
	for _, t := range out.SessionTokens {
		token, err := uuid.Parse(t)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, token)
	}
	return tokens, nil
}

// Terminates the session associated with the provided token.
func (c *Client) TerminateSession(token uuid.UUID) error {
	req, _ := http.NewRequest(http.MethodDelete, c.base+"/v1/sessions/"+token.String(), nil)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent {
		msg, err := readJSONError(resp)
		if err != nil {
			return fmt.Errorf("terminateSession: status=%s", resp.Status)
		}
		return fmt.Errorf("terminateSession: status=%s error=%s", resp.Status, msg)
	}
	return nil
}

// Retrieves statistics for the session associated with the provided token.
func (c *Client) SessionStats(token uuid.UUID) (*et.SessionStats, error) {
	req, _ := http.NewRequest(http.MethodGet, c.base+"/v1/sessions/"+token.String()+"/stats", nil)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		msg, err := readJSONError(resp)
		if err != nil {
			return nil, fmt.Errorf("%s/stats: status=%s", token.String(), resp.Status)
		}
		return nil, fmt.Errorf("%s/stats: status=%s error=%s", token.String(), resp.Status, msg)
	}

	var st et.SessionStats
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return nil, err
	}
	return &st, nil
}

// Retrieves scope for the session associated with the provided token.
func (c *Client) SessionScope(token uuid.UUID, atype oam.AssetType) ([]oam.Asset, error) {
	sessionID := token.String()
	atypestr := strings.ToLower(string(atype))
	u := fmt.Sprintf("%s/v1/sessions/%s/scope/%s", c.base, sessionID, atypestr)
	req, _ := http.NewRequest(http.MethodGet, u, nil)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		msg, err := readJSONError(resp)
		if err != nil {
			return nil, fmt.Errorf("%s/scope: status=%s", token.String(), resp.Status)
		}
		return nil, fmt.Errorf("%s/scope: status=%s error=%s", token.String(), resp.Status, msg)
	}

	return decodeAssetsForScopeEndpoint(atype, resp.Body)
}

// Creates a new asset on the server associated with the provided token.
func (c *Client) CreateAsset(token uuid.UUID, asset oam.Asset) (string, error) {
	atype := strings.ToLower(string(asset.AssetType()))
	raw, err := asset.JSON()
	if err != nil {
		return "", err
	}

	sessionID := token.String()
	u := fmt.Sprintf("%s/v1/sessions/%s/assets/%s", c.base, sessionID, atype)
	req, _ := http.NewRequest(http.MethodPost, u, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		msg, err := readJSONError(resp)
		if err != nil {
			return "", fmt.Errorf("createAsset: status=%s", resp.Status)
		}
		return "", fmt.Errorf("createAsset: status=%s error=%s", resp.Status, msg)
	}

	var r AddAssetResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", err
	}
	return r.EntityID, nil
}

// Creates multiple assets in bulk on the server associated with the provided token.
func (c *Client) CreateAssetsBulk(token uuid.UUID, atype string, assets []oam.Asset) (int, error) {
	atype = strings.ToLower(strings.TrimSpace(atype))

	if atype == "" {
		return 0, fmt.Errorf("CreateAssetsBulk: asset type required")
	}
	if len(assets) > MaxBulkItems {
		return 0, fmt.Errorf("CreateAssetsBulk: too many items; max=%d", MaxBulkItems)
	}

	items := make([]json.RawMessage, 0, len(assets))
	for _, asset := range assets {
		if !strings.EqualFold(atype, string(asset.AssetType())) {
			return 0, fmt.Errorf("CreateAssetsBulk: mixed asset types not allowed")
		}

		raw, err := asset.JSON()
		if err != nil {
			return 0, err
		}
		items = append(items, json.RawMessage(raw))
	}

	sessionID := token.String()
	u := fmt.Sprintf("%s/v1/sessions/%s/assets/%s:bulk", c.base, sessionID, atype)

	body, _ := json.Marshal(BulkAddAssetsRequest{Items: items})
	req, _ := http.NewRequest(http.MethodPost, u, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		msg, err := readJSONError(resp)
		if err != nil {
			return 0, fmt.Errorf("addAssetsBulk: status=%s", resp.Status)
		}
		return 0, fmt.Errorf("addAssetsBulk: status=%s error=%s", resp.Status, msg)
	}

	var out BulkAddAssetsResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return 0, err
	}
	return int(out.Stored), nil
}

// Subscribe to receive a stream of log messages from the server.
func (c *Client) Subscribe(token uuid.UUID) (<-chan string, error) {
	u, err := url.Parse(c.base)
	if err != nil {
		return nil, err
	}

	switch u.Scheme {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	}

	sessionID := token.String()
	u.Path = "/v1/sessions/" + sessionID + "/ws/logs"

	conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		return nil, err
	}
	c.wsClient = conn

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	ch := make(chan string)
	// Receive go routine
	go func() {
		for {
			select {
			case <-c.done:
				_ = c.wsClient.WriteMessage(websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.CloseNormalClosure, "bye"))
				return
			case <-interrupt:
				_ = c.wsClient.WriteMessage(websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.CloseNormalClosure, "bye"))
				return
			default:
				_, message, err := c.wsClient.ReadMessage()
				if err != nil {
					return
				}
				ch <- string(message)
			}
		}
	}()
	return ch, nil
}

func readJSONError(resp *http.Response) (string, error) {
	var errResp struct {
		Message string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
		return "", err
	}
	return errResp.Message, nil
}
