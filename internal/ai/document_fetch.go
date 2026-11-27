// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/docmeta"
	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// DocumentFetcher gets a stored document's text for the document model to
// read, with the content hash of the version it got. The Asset Database keeps
// no copy of a document's content, so the document is fetched when it is
// read.
type DocumentFetcher interface {
	Document(ctx context.Context, src lens.DocumentSource) (text, sha256 string, err error)
}

// HTTPFetcher fetches documents over HTTP(S), from the web archive copy the
// engine read when it read one (so the target is not contacted again),
// otherwise from the document's URL, and extracts their text in memory.
type HTTPFetcher struct {
	Client *http.Client
}

// Document implements DocumentFetcher.
func (f HTTPFetcher) Document(ctx context.Context, src lens.DocumentSource) (string, string, error) {
	doc, err := fetchDocument(ctx, f, src)
	return doc.text, doc.sha256, err
}

// defaultFetchTimeout bounds one document download.
const defaultFetchTimeout = 4 * time.Minute

// Fetch implements DocumentFetcher, refusing a document longer than max.
func (f HTTPFetcher) Fetch(ctx context.Context, u string, max int64) ([]byte, error) {
	client := f.Client
	if client == nil {
		client = &http.Client{Timeout: defaultFetchTimeout}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "OWASP Amass document reader")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %s", resp.Status)
	}
	if max > 0 && resp.ContentLength > max {
		return nil, tooLargeError{max: max}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if max > 0 && int64(len(data)) > max {
		return nil, tooLargeError{max: max}
	}
	return data, nil
}

// tooLargeError is a document longer than the documents rules allow.
type tooLargeError struct{ max int64 }

func (e tooLargeError) Error() string { return fmt.Sprintf("larger than %d bytes", e.max) }

// fetchedDocument is a document fetched again for reading: its text and the
// content hash of the version fetched.
type fetchedDocument struct {
	text   string
	sha256 string
}

// fetchDocument fetches a stored document again, from the web archive copy
// the engine read when it read one (so the target is not contacted again),
// otherwise from its URL, and extracts its text and links in memory.
func fetchDocument(ctx context.Context, f HTTPFetcher, src lens.DocumentSource) (fetchedDocument, error) {
	var out fetchedDocument
	rules := semantics.Documents()
	dt, ok := rules.DocumentFor(documentPath(src.URL))
	if !ok {
		return out, &documentError{kind: FailureUnsupported, err: errors.New("not a document type Amass reads")}
	}

	from := src.URL
	if src.RetrievedFrom != "" {
		from = src.RetrievedFrom
	}
	data, err := f.Fetch(ctx, from, rules.MaxBytes)
	if err != nil {
		kind := FailureFetch
		if errors.As(err, new(tooLargeError)) {
			kind = FailureTooLarge
		}
		return out, &documentError{kind: kind, err: fmt.Errorf("fetch: %w", err)}
	}
	sum := sha256.Sum256(data)
	out.sha256 = hex.EncodeToString(sum[:])

	content, err := docmeta.ExtractContent(dt.Format, data)
	if err != nil {
		return out, &documentError{kind: FailureExtract, err: fmt.Errorf("extract text: %w", err)}
	}
	out.text = strings.TrimSpace(content.Text + "\n" + strings.Join(content.Links, "\n"))
	return out, nil
}

// documentPath returns the path of a document URL, for its type.
func documentPath(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Path != "" {
		return u.Path
	}
	return path.Base(raw)
}
