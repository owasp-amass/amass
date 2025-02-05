// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/owasp-amass/amass/v4/config"
	et "github.com/owasp-amass/amass/v4/engine/types"
)

type Handler func(message string)

type Client struct {
	url        string
	httpClient http.Client
	wsClient   *websocket.Conn
}

func NewClient(url string) *Client {
	return &Client{url: url, httpClient: http.Client{}}
}

func (c *Client) Query(query string) (string, error) {
	quoted := strings.Trim(strconv.Quote((string(query))), `"`)
	b := []byte(fmt.Sprintf(`{"query":"%s"}`, quoted))

	req, err := http.NewRequest(http.MethodPost, c.url, bytes.NewBuffer(b))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	} else if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("response indicated status: %s", res.Status)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// Create a session by sending the config elements as graphql named fields
// TODO: Not Implemented. The transfromations use "->" in the config YAML,
// but that is not a valid field name in GraphQL
func (c *Client) CreateSession(config *config.Config) (uuid.UUID, error) {
	var token uuid.UUID
	configJson, err := json.Marshal(config)
	if err != nil {
		return token, err
	}

	quoted := strings.Trim(strconv.Quote((string(configJson))), `"`)
	query := fmt.Sprintf(`mutation { createSessionFromJson(input: {config: "%s"}) {sessionToken} }`, quoted)

	res, err := c.Query(query)
	if err != nil {
		return token, err
	}

	var resp struct {
		Data struct{ CreateSessionFromJson struct{ SessionToken string } }
	}
	if err := json.Unmarshal([]byte(res), &resp); err != nil {
		return token, err
	}

	return uuid.Parse(resp.Data.CreateSessionFromJson.SessionToken)
}

func (c *Client) CreateAsset(asset et.Asset, token uuid.UUID) error {
	asset.Session = token
	assetJson, err := json.Marshal(asset)
	if err != nil {
		return err
	}

	var data interface{}
	if err := json.Unmarshal(assetJson, &data); err != nil {
		return err
	}
	q := gqlEncoder(data)

	queryStr := fmt.Sprintf(`mutation { createAsset(input: %s) {id} }`, string(q))
	if _, err := c.Query(queryStr); err != nil {
		return err
	}
	return nil
}

func (c *Client) TerminateSession(token uuid.UUID) {
	_, _ = c.Query(fmt.Sprintf(`mutation { terminateSession(sessionToken: "%s") }`, token.String()))
}

func (c *Client) SessionStats(token uuid.UUID) (*et.SessionStats, error) {
	queryStr := fmt.Sprintf(`query { sessionStats(sessionToken: "%s"){
		WorkItemsCompleted 
		WorkItemsTotal} }`, token.String())

	res, err := c.Query(queryStr)
	if err != nil {
		return &et.SessionStats{}, err
	}

	var gqlResp struct {
		Data struct{ SessionStats et.SessionStats }
	}
	if err := json.Unmarshal([]byte(res), &gqlResp); err != nil {
		return &et.SessionStats{}, err
	}
	return &gqlResp.Data.SessionStats, nil
}

// Creates subscription to receove a stream of log messages from the sever
func (c *Client) Subscribe(token uuid.UUID) (<-chan string, error) {
	parsedURL, _ := url.Parse(c.url)
	parsedURL.Scheme = "ws"
	id := uuid.New().String()

	conn, _, err := websocket.DefaultDialer.Dial(parsedURL.String(), nil)
	if err != nil {
		return nil, err
	}
	c.wsClient = conn

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	// Subprotocol Init
	message := fmt.Sprintf(`{"type": "connection_init","id": "%s","payload": {}}`, id)
	err = conn.WriteMessage(websocket.TextMessage, []byte(message))
	if err != nil {
		return nil, err
	}

	// Start the subscription
	id = uuid.New().String()
	message = fmt.Sprintf(`{"type": "start", "id":"%s", "payload":{"query":"subscription { logMessages(sessionToken: \"%s\")}"} }`, id, token.String())
	err = conn.WriteMessage(websocket.TextMessage, []byte(message))
	if err != nil {
		return nil, err
	}

	ch := make(chan string)
	// Receive go routine
	go func() {
		for {
			select {
			case <-interrupt:
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

// Converts unmarshalled JSON into graphql field syntax
// This is a simple function for testing
func gqlEncoder(data interface{}) string {
	var q string

	switch data := data.(type) {
	case map[string]interface{}:
		q += "{"
		for key, val := range data {
			q += fmt.Sprintf("%s: %v,", key, gqlEncoder(val))
		}
		q = strings.TrimRight(q, ", ")
		q += "}"
	case []interface{}:
		q += "["
		for _, val := range data {
			q += fmt.Sprintf("%v, ", gqlEncoder(val))
		}
		q = strings.TrimRight(q, ", ")
		q += "]"
	case string:
		q += fmt.Sprintf("\"%s\"", data)
	default:
		q += fmt.Sprintf("%v", data)
	}
	return q
}
