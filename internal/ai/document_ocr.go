// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/internal/ai/llm"
	"github.com/owasp-amass/amass/v5/internal/docmeta"
)

// PageReader reads the text of a scanned document from the pictures of its
// pages.
type PageReader interface {
	ReadPages(ctx context.Context, pages []docmeta.PageImage) (string, error)
}

// ErrNoPageReader is a scanned document's answer when neither the document
// model can see pictures nor Tesseract is installed.
var ErrNoPageReader = errors.New("scanned pages need a document model that reads pictures or Tesseract")

// The bounds on reading scanned pages.
const (
	// maxScannedPages bounds the pages of one document read.
	maxScannedPages = 64
	// pageTimeout bounds Tesseract's reading of one page.
	pageTimeout = 2 * time.Minute
	// minDocumentText is the least text a PDF gives without its pages being
	// read as pictures: a scan carries none, or only a stamp or a page
	// number.
	minDocumentText = 200
)

// transcribePrompt asks a model that sees a page to write out its text.
const transcribePrompt = "This is a picture of one page of a scanned document. Write out all of the text on " +
	"the page exactly as written, in reading order, keeping line breaks. Reply with only the text; if the page " +
	"has none, reply with nothing."

// DocumentPages returns the page reader for the document model: the model
// itself when it can see pictures (options.ai.documents.vision), otherwise
// Tesseract when it is installed. It decides the first time it is asked.
func DocumentPages(d *config.DocumentModelSettings, model llm.Model) PageReader {
	return &pageReader{settings: d, model: model, tesseract: "tesseract"}
}

type pageReader struct {
	settings  *config.DocumentModelSettings
	model     llm.Model
	tesseract string

	once   sync.Once
	vision bool
	ocr    string
}

// ReadPages implements PageReader.
func (p *pageReader) ReadPages(ctx context.Context, pages []docmeta.PageImage) (string, error) {
	p.once.Do(func() {
		p.vision = p.model != nil && canSee(ctx, p.settings)
		if !p.vision {
			if path, err := exec.LookPath(p.tesseract); err == nil {
				p.ocr = path
			}
		}
	})

	if len(pages) > maxScannedPages {
		pages = pages[:maxScannedPages]
	}
	switch {
	case p.vision:
		return transcribe(ctx, p.model, pages)
	case p.ocr != "":
		return tesseract(ctx, p.ocr, pages)
	}
	return "", ErrNoPageReader
}

// canSee reports whether the document model reads pictures: as the settings
// say, or by its provider when they leave it to auto.
func canSee(ctx context.Context, d *config.DocumentModelSettings) bool {
	if d == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(d.Vision)) {
	case "on":
		return true
	case "off":
		return false
	}

	switch strings.ToLower(strings.TrimSpace(d.Provider)) {
	case "anthropic":
		return true
	case "ollama":
		m := llm.NewOllamaModel(d.Endpoint, d.Model, nil)
		ok, err := m.Capable(ctx, "vision")
		return err == nil && ok
	}
	return false
}

// transcribe has a model that sees pictures write out each page's text.
func transcribe(ctx context.Context, model llm.Model, pages []docmeta.PageImage) (string, error) {
	var b strings.Builder
	for i, page := range pages {
		if err := ctx.Err(); err != nil {
			return b.String(), err
		}

		resp, err := model.Generate(ctx, []llm.Message{{Role: "user", Text: transcribePrompt,
			Images: []llm.Image{{MediaType: page.MediaType, Data: page.Data}}}}, nil)
		if err != nil {
			return b.String(), fmt.Errorf("page %d of %d: %w", i+1, len(pages), err)
		}
		writePage(&b, resp.Text)
	}
	return b.String(), nil
}

// tesseract reads each page's text with the Tesseract program at path.
func tesseract(ctx context.Context, path string, pages []docmeta.PageImage) (string, error) {
	var b strings.Builder
	for i, page := range pages {
		pctx, cancel := context.WithTimeout(ctx, pageTimeout)
		cmd := exec.CommandContext(pctx, path, "stdin", "stdout", "--psm", "1")
		cmd.Stdin = bytes.NewReader(page.Data)
		var out, errOut bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errOut
		err := cmd.Run()
		cancel()
		if err != nil {
			return b.String(), fmt.Errorf("page %d of %d: tesseract: %w: %s", i+1, len(pages), err,
				strings.TrimSpace(errOut.String()))
		}
		writePage(&b, out.String())
	}
	return b.String(), nil
}

// writePage adds one page's text, separated from the page before.
func writePage(b *strings.Builder, text string) {
	if text = strings.TrimSpace(text); text == "" {
		return
	}
	if b.Len() > 0 {
		b.WriteString("\n\n")
	}
	b.WriteString(text)
}

// scanned reports whether a PDF's text is too little to be its content, so
// its pages are pictures of text.
func scanned(format, text string) bool {
	return format == docmeta.FormatPDF && len(strings.TrimSpace(text)) < minDocumentText
}
