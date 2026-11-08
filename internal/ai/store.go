// SPDX-License-Identifier: Apache-2.0
package ai

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ReviewEvent is separate from OAM. No edge is inserted automatically.
type ReviewEvent struct {
	ProposalID string    `json:"proposal_id"`
	Status     string    `json:"status"`
	Actor      string    `json:"actor"`
	At         time.Time `json:"at"`
}
type Journal struct {
	Path string
	mu   sync.Mutex
}

func (j *Journal) append(kind string, body any) error {
	if j == nil || j.Path == "" {
		return errors.New("journal path required")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(j.Path), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(j.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := json.Marshal(map[string]any{"kind": kind, "data": body})
	if err != nil {
		return err
	}
	if _, err = f.Write(append(data, '\n')); err != nil {
		return err
	}
	return f.Sync()
}
func (j *Journal) Submit(p Proposal) error {
	if p.ID == "" || p.Status != "proposed" {
		return errors.New("proposal must be proposed and have ID")
	}
	return j.append("proposal", p)
}
func (j *Journal) Review(id, status, actor string) error {
	if id == "" || actor == "" {
		return errors.New("proposal ID and reviewer required")
	}
	if status != "accepted" && status != "rejected" && status != "superseded" {
		return fmt.Errorf("invalid status %q", status)
	}
	return j.append("review", ReviewEvent{ProposalID: id, Status: status, Actor: actor, At: time.Now().UTC()})
}
func (j *Journal) History() ([]json.RawMessage, error) {
	f, err := os.Open(j.Path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 4096), 1<<20)
	var lines []json.RawMessage
	for s.Scan() {
		if !json.Valid(s.Bytes()) {
			return nil, errors.New("malformed journal entry")
		}
		lines = append(lines, append([]byte(nil), s.Bytes()...))
	}
	return lines, s.Err()
}
