// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/owasp-amass/amass/v5/config"
	apiclient "github.com/owasp-amass/amass/v5/engine/api/client"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	oam "github.com/owasp-amass/open-asset-model"
)

const MaxBulkItems = 1000

type Client struct {
	base       string
	httpClient *http.Client
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
func NewClient(url string) (*Client, error) {
	return &Client{
		base:       url + "/api/v1",
		httpClient: amasshttp.DefaultClient,
		done:       make(chan struct{}),
	}, nil
}

// Close terminates any open connections associated with the client.
func (c *Client) Close() {
	close(c.done)
}

// HealthCheck returns true when the client was able to reach the server.
func (c *Client) HealthCheck(ctx context.Context) bool {
	resp, err := amasshttp.RequestWebPage(ctx, c.httpClient, &amasshttp.Request{URL: c.base + "/health"})
	if err != nil {
		return false
	}
	return resp.StatusCode == http.StatusOK
}

// Creates a new session on the server with the provided configuration.
func (c *Client) CreateSession(ctx context.Context, config *config.Config) (uuid.UUID, error) {
	raw, err := json.Marshal(config)
	if err != nil {
		return uuid.UUID{}, err
	}

	resp, err := amasshttp.RequestWebPage(ctx, c.httpClient, &amasshttp.Request{
		Method: http.MethodPost,
		Body:   string(raw),
		URL:    c.base + "/sessions",
		Header: amasshttp.Header{"Content-Type": []string{"application/json"}},
	})
	if err != nil {
		return uuid.UUID{}, err
	}

	if resp.StatusCode != http.StatusCreated {
		msg, err := readJSONError(resp.Body)
		if err != nil {
			return uuid.UUID{}, fmt.Errorf("createSession: status=%s", resp.Status)
		}
		return uuid.UUID{}, fmt.Errorf("createSession: status=%s error=%s", resp.Status, msg)
	}

	var out CreateSessionResponse
	if err := json.Unmarshal([]byte(resp.Body), &out); err != nil {
		return uuid.UUID{}, err
	}

	return uuid.Parse(out.SessionToken)
}

// Lists the active session and associated tokens on the server.
func (c *Client) ListSessions(ctx context.Context) ([]uuid.UUID, error) {
	resp, err := amasshttp.RequestWebPage(ctx, c.httpClient, &amasshttp.Request{URL: c.base + "/sessions/list"})
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		msg, err := readJSONError(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("listSessions: status=%s", resp.Status)
		}
		return nil, fmt.Errorf("listSessions: status=%s error=%s", resp.Status, msg)
	}

	var out ListSessionsResponse
	if err := json.Unmarshal([]byte(resp.Body), &out); err != nil {
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
func (c *Client) TerminateSession(ctx context.Context, token uuid.UUID) error {
	resp, err := amasshttp.RequestWebPage(ctx, c.httpClient, &amasshttp.Request{
		Method: http.MethodDelete,
		URL:    c.base + "/sessions/" + token.String(),
	})
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusNoContent {
		msg, err := readJSONError(resp.Body)
		if err != nil {
			return fmt.Errorf("terminateSession: status=%s", resp.Status)
		}
		return fmt.Errorf("terminateSession: status=%s error=%s", resp.Status, msg)
	}
	return nil
}

// Retrieves statistics for the session associated with the provided token.
func (c *Client) SessionStats(ctx context.Context, token uuid.UUID) (*et.SessionStats, error) {
	resp, err := amasshttp.RequestWebPage(ctx, c.httpClient,
		&amasshttp.Request{URL: c.base + "/sessions/" + token.String() + "/stats"})
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		msg, err := readJSONError(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("%s/stats: status=%s", token.String(), resp.Status)
		}
		return nil, fmt.Errorf("%s/stats: status=%s error=%s", token.String(), resp.Status, msg)
	}

	var st et.SessionStats
	if err := json.Unmarshal([]byte(resp.Body), &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// Retrieves scope for the session associated with the provided token.
func (c *Client) SessionScope(ctx context.Context, token uuid.UUID, atype oam.AssetType) ([]oam.Asset, error) {
	sessionID := token.String()
	atypestr := strings.ToLower(string(atype))
	u := fmt.Sprintf("%s/sessions/%s/scope/%s", c.base, sessionID, atypestr)
	resp, err := amasshttp.RequestWebPage(ctx, c.httpClient, &amasshttp.Request{URL: u})
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		msg, err := readJSONError(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("%s/scope: status=%s", token.String(), resp.Status)
		}
		return nil, fmt.Errorf("%s/scope: status=%s error=%s", token.String(), resp.Status, msg)
	}

	reader := strings.NewReader(resp.Body)
	readCloser := io.NopCloser(reader)
	defer func() { _ = readCloser.Close() }()

	return apiclient.DecodeAssetsForScopeEndpoint(atype, readCloser)
}

// Creates a new asset on the server associated with the provided token.
func (c *Client) CreateAsset(ctx context.Context, token uuid.UUID, asset oam.Asset) (string, error) {
	atype := strings.ToLower(string(asset.AssetType()))
	raw, err := asset.JSON()
	if err != nil {
		return "", err
	}

	sessionID := token.String()
	u := fmt.Sprintf("%s/sessions/%s/assets/%s", c.base, sessionID, atype)
	resp, err := amasshttp.RequestWebPage(ctx, c.httpClient, &amasshttp.Request{
		URL:    u,
		Body:   string(raw),
		Method: http.MethodPost,
		Header: amasshttp.Header{"Content-Type": []string{"application/json"}},
	})
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		msg, err := readJSONError(resp.Body)
		if err != nil {
			return "", fmt.Errorf("createAsset: status=%s", resp.Status)
		}
		return "", fmt.Errorf("createAsset: status=%s error=%s", resp.Status, msg)
	}

	var r AddAssetResponse
	if err := json.Unmarshal([]byte(resp.Body), &r); err != nil {
		return "", err
	}
	return r.EntityID, nil
}

// Creates multiple assets in bulk on the server associated with the provided token.
func (c *Client) CreateAssetsBulk(ctx context.Context, token uuid.UUID, atype string, assets []oam.Asset) (int, error) {
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
	body, _ := json.Marshal(BulkAddAssetsRequest{Items: items})
	u := fmt.Sprintf("%s/sessions/%s/assets/%s:bulk", c.base, sessionID, atype)
	resp, err := amasshttp.RequestWebPage(ctx, c.httpClient, &amasshttp.Request{
		URL:    u,
		Body:   string(body),
		Method: http.MethodPost,
		Header: amasshttp.Header{"Content-Type": []string{"application/json"}},
	})
	if err != nil {
		return 0, err
	}

	if resp.StatusCode != http.StatusOK {
		msg, err := readJSONError(resp.Body)
		if err != nil {
			return 0, fmt.Errorf("addAssetsBulk: status=%s", resp.Status)
		}
		return 0, fmt.Errorf("addAssetsBulk: status=%s error=%s", resp.Status, msg)
	}

	var out BulkAddAssetsResponse
	if err := json.Unmarshal([]byte(resp.Body), &out); err != nil {
		return 0, err
	}
	return int(out.Stored), nil
}

// Subscribe to receive a stream of log messages from the server.
func (c *Client) Subscribe(ctx context.Context, token uuid.UUID) (<-chan string, error) {
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
	u.Path += "/sessions/" + sessionID + "/ws/logs"

	conn, _, err := websocket.DefaultDialer.DialContext(ctx, u.String(), nil)
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

func readJSONError(content string) (string, error) {
	var errResp struct {
		Message string `json:"error"`
	}
	if err := json.Unmarshal([]byte(content), &errResp); err != nil {
		return "", err
	}
	return errResp.Message, nil
}
