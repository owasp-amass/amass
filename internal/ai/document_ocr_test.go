// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/internal/ai/llm"
	"github.com/owasp-amass/amass/v5/internal/docmeta"
)

// seeingModel answers each page with its text and keeps what it was shown.
type seeingModel struct{ shown []llm.Image }

func (m *seeingModel) Generate(_ context.Context, h []llm.Message, _ []llm.ToolSpec) (llm.Response, error) {
	m.shown = append(m.shown, h[0].Images...)
	return llm.Response{Text: "page text"}, nil
}

func TestPageReaders(t *testing.T) {
	pages := []docmeta.PageImage{{MediaType: "image/jpeg", Data: []byte{1}}, {MediaType: "image/jpeg", Data: []byte{2}}}
	ctx := context.Background()

	// a model that sees pictures is shown each page
	model := &seeingModel{}
	text, err := DocumentPages(&config.DocumentModelSettings{Provider: "compatible", Vision: "on"}, model).
		ReadPages(ctx, pages)
	if err != nil || text != "page text\n\npage text" || len(model.shown) != 2 {
		t.Errorf("vision: %q, %v, %d pages shown", text, err, len(model.shown))
	}

	// an Anthropic model sees pictures without being told
	if !canSee(ctx, &config.DocumentModelSettings{Provider: "anthropic"}) ||
		canSee(ctx, &config.DocumentModelSettings{Provider: "compatible"}) ||
		canSee(ctx, &config.DocumentModelSettings{Provider: "anthropic", Vision: "off"}) {
		t.Error("vision by provider")
	}

	// neither a seeing model nor Tesseract leaves the scan without text
	none := &pageReader{settings: &config.DocumentModelSettings{Vision: "off"}, model: &seeingModel{},
		tesseract: "no-such-ocr-program"}
	if _, err := none.ReadPages(ctx, pages); !errors.Is(err, ErrNoPageReader) {
		t.Errorf("without a reader: %v", err)
	}

	// otherwise Tesseract reads the pages
	if runtime.GOOS == "windows" {
		return
	}
	fake := filepath.Join(t.TempDir(), "tesseract")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\ncat >/dev/null\necho scanned words\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	ocr := &pageReader{settings: &config.DocumentModelSettings{Vision: "off"}, model: &seeingModel{}, tesseract: fake}
	if text, err := ocr.ReadPages(ctx, pages); err != nil || strings.Count(text, "scanned words") != 2 {
		t.Errorf("tesseract: %q, %v", text, err)
	}
}

func TestScanned(t *testing.T) {
	if !scanned(docmeta.FormatPDF, " 3 ") || scanned(docmeta.FormatPDF, strings.Repeat("words ", 50)) ||
		scanned(docmeta.FormatOOXML, "") {
		t.Error("scanned")
	}
}
