// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// AISettings is an opt-in set of model and investigation defaults. No model
// requests, network listeners, or collection tasks start just because this
// section is present. CLI flags override env vars, which override this YAML.
type AISettings struct {
	Provider             string `yaml:"provider,omitempty" json:"provider,omitempty"`
	Endpoint             string `yaml:"endpoint,omitempty" json:"endpoint,omitempty"`
	Model                string `yaml:"model,omitempty" json:"model,omitempty"`
	APIKeyEnv            string `yaml:"api_key_env,omitempty" json:"api_key_env,omitempty"`
	AllowHTTP            bool   `yaml:"allow_http,omitempty" json:"allow_http,omitempty"`
	ModelTimeout         string `yaml:"model_timeout,omitempty" json:"model_timeout,omitempty"`
	InvestigationTimeout string `yaml:"investigation_timeout,omitempty" json:"investigation_timeout,omitempty"`
	ClassifierModel      string `yaml:"classifier_model,omitempty" json:"classifier_model,omitempty"`
	ClassifierEndpoint   string `yaml:"classifier_endpoint,omitempty" json:"classifier_endpoint,omitempty"`
	ClassifierReview     bool   `yaml:"classifier_review,omitempty" json:"classifier_review,omitempty"`
	MaxDepth             int    `yaml:"depth,omitempty" json:"depth,omitempty"`
	MaxMatches           int    `yaml:"max_matches,omitempty" json:"max_matches,omitempty"`
	MaxPathsPerAsset     int    `yaml:"max_paths_per_asset,omitempty" json:"max_paths_per_asset,omitempty"`
	MaxExpansions        int    `yaml:"max_expansions,omitempty" json:"max_expansions,omitempty"`
	GuidanceRounds       int    `yaml:"guidance_rounds,omitempty" json:"guidance_rounds,omitempty"`
	// MaxTokens caps each model reply; 0 keeps the provider default.
	MaxTokens int `yaml:"max_tokens,omitempty" json:"max_tokens,omitempty"`
	// Temperature is a decimal 0..2; empty keeps the provider default.
	Temperature string `yaml:"temperature,omitempty" json:"temperature,omitempty"`
	// ContextTokens sets the Ollama context window; 0 keeps the default.
	ContextTokens int `yaml:"context_tokens,omitempty" json:"context_tokens,omitempty"`
	// Think enables an Ollama reasoning model's thinking phase (off by default).
	Think bool `yaml:"think,omitempty" json:"think,omitempty"`
	// Attribution controls ownership attribution during enumeration: "auto"
	// (the default) writes strong proposals and journals the rest, "journal"
	// only journals them, and "off" turns it off. It needs no model.
	Attribution string `yaml:"attribution,omitempty" json:"attribution,omitempty"`
	// AttributionCanaryEvery checks the attribution passes' lasting cache:
	// every N passes, each organization is also searched without it and a
	// difference is logged. Zero (the default) never checks.
	AttributionCanaryEvery int `yaml:"attribution_canary_every,omitempty" json:"attribution_canary_every,omitempty"`
	// Journal is the review journal path; empty uses review.jsonl in the
	// Amass output directory.
	Journal string `yaml:"journal,omitempty" json:"journal,omitempty"`
	// AnnounceDecisions controls whether the classifier's applied decisions and
	// new proposals are announced proactively (the end-of-run summary and the
	// assistant push). Nil means the default — on whenever attribution is not
	// off; set false to silence the announcements without changing attribution.
	AnnounceDecisions *bool `yaml:"announce_decisions,omitempty" json:"announce_decisions,omitempty"`
	// ClassifierApplies lets a classifier trained from people's review
	// decisions (amass ai train) apply its confident answers on its own,
	// under attribution auto, for the questions where it only advises by
	// default (whether a name is a person's or an organization's). Off: its
	// answers are kept as advice, and the main model, if set, decides.
	ClassifierApplies bool `yaml:"classifier_applies,omitempty" json:"classifier_applies,omitempty"`
	// Documents names the one model allowed to read the content of collected
	// documents. It is separate from the model above and never falls back to
	// it: without it, no model reads documents.
	Documents *DocumentModelSettings `yaml:"documents,omitempty" json:"documents,omitempty"`
	// Contributions governs what assistants add to the Asset Database with
	// the MCP contribute tool.
	Contributions *ContributionSettings `yaml:"contributions,omitempty" json:"contributions,omitempty"`
}

// ContributionSettings govern the assets, relations and properties
// assistants contribute, recorded under amass-ai:<client> sources.
type ContributionSettings struct {
	// StrongEvidence lets a contribution be strong evidence: a strong signal
	// whose every witness only an assistant recorded. Off, such a signal
	// still counts, as supporting evidence.
	StrongEvidence bool `yaml:"strong_evidence,omitempty" json:"strong_evidence,omitempty"`
}

// DocumentModelSettings choose the model that reads collected documents, all
// of each one's text, to find what they state in Open Asset Model terms: the
// assets they name (hosts, networks, organizations, people, products,
// addresses), the relations between them and the values of their fields. The
// Asset Database keeps no copy of a document; the reader fetches it when it
// reads it. A document can hold personal or internal details, so the user
// names this model explicitly, and other models see its findings only when
// ShareWithAssistants is set.
type DocumentModelSettings struct {
	// Enabled turns the document model on; off by default.
	Enabled bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	// Provider is ollama, compatible (an OpenAI-compatible chat API) or
	// anthropic, as for the main model.
	Provider  string `yaml:"provider,omitempty" json:"provider,omitempty"`
	Endpoint  string `yaml:"endpoint,omitempty" json:"endpoint,omitempty"`
	Model     string `yaml:"model,omitempty" json:"model,omitempty"`
	APIKeyEnv string `yaml:"api_key_env,omitempty" json:"api_key_env,omitempty"`
	// AllowHTTP permits a plain HTTP endpoint, for a model on a trusted
	// private network only.
	AllowHTTP bool `yaml:"allow_http,omitempty" json:"allow_http,omitempty"`
	// ModelTimeout bounds one request: one chunk of a document.
	ModelTimeout string `yaml:"model_timeout,omitempty" json:"model_timeout,omitempty"`
	// ContextTokens sets an Ollama model's context window (default 16384,
	// enough for a chunk and the instructions).
	ContextTokens int `yaml:"context_tokens,omitempty" json:"context_tokens,omitempty"`
	// ChunkChars is how many characters of a document one request reads
	// (default 12000); a document is read whole, chunk by chunk.
	ChunkChars int `yaml:"chunk_chars,omitempty" json:"chunk_chars,omitempty"`
	// MaxTokens caps one reply (default 4096). A reply cut off at the cap is
	// incomplete, so that chunk is skipped and the rest of the document is
	// still read; without a cap a model that repeats itself fills the whole
	// context window before it stops.
	MaxTokens int `yaml:"max_tokens,omitempty" json:"max_tokens,omitempty"`
	// ShareWithAssistants lets other models (the main investigation model and
	// MCP clients) read the document model's findings, which quote the
	// documents. Off by default: they then see only counts.
	ShareWithAssistants bool `yaml:"share_with_assistants,omitempty" json:"share_with_assistants,omitempty"`
	// MaxLeads caps the leads the document model hands one supervised
	// enumeration. The budget adapts on its own: it starts at 50, grows by 2
	// for each lead the engine confirms while at least half are confirmed,
	// and never passes one lead per 10 work items the run has completed. 0
	// leaves it at that, a positive value caps it lower, -1 submits none
	// while findings are still stored.
	MaxLeads int `yaml:"max_leads,omitempty" json:"max_leads,omitempty"`
	// Hold bounds how long a supervised enumeration whose engine work is
	// done stays open while the document model still has documents to read,
	// so their leads reach the run (default 15m; 0 ends the run when the
	// engine is done). The hold also ends once the documents left would not
	// be read within it. Documents left unread are read by the next run or
	// read_documents.
	Hold string `yaml:"hold,omitempty" json:"hold,omitempty"`
	// DocumentTimeout bounds the time one reading spends on one document
	// (default 10m; 0 sets no bound). Past it no further chunk is started; the
	// document's next reading continues where this one stopped. A fast model
	// reads whole documents within it; a slow one leaves the rest of a long
	// document for later passes and runs.
	DocumentTimeout string `yaml:"document_timeout,omitempty" json:"document_timeout,omitempty"`
	// MaxChunks caps the chunks one reading takes from one document (0, the
	// default, sets no cap), mainly to bound the tokens a hosted model is
	// paid for; the rest is read by the next reading.
	MaxChunks int `yaml:"max_chunks,omitempty" json:"max_chunks,omitempty"`
}

// DefaultDocumentTimeout bounds one reading of one document when
// options.ai.documents.document_timeout is not set.
const DefaultDocumentTimeout = 10 * time.Minute

// DocumentTimeoutDuration returns DocumentTimeout, DefaultDocumentTimeout when
// it is not set, and 0 (no bound) when it is set to 0.
func (d *DocumentModelSettings) DocumentTimeoutDuration() time.Duration {
	if d == nil || strings.TrimSpace(d.DocumentTimeout) == "" {
		return DefaultDocumentTimeout
	}

	v, err := time.ParseDuration(strings.TrimSpace(d.DocumentTimeout))
	if err != nil || v < 0 {
		return DefaultDocumentTimeout
	}
	return v
}

// HoldDuration returns Hold, and false when it is not set.
func (d *DocumentModelSettings) HoldDuration() (time.Duration, bool) {
	if d == nil || strings.TrimSpace(d.Hold) == "" {
		return 0, false
	}

	v, err := time.ParseDuration(strings.TrimSpace(d.Hold))
	if err != nil {
		return 0, false
	}
	return v, true
}

// DocumentModelProviders are the providers the document model may use.
var DocumentModelProviders = []string{"ollama", "compatible", "anthropic"}

// Validate checks enabled document model settings; disabled ones are not
// checked, so a commented or partial section never stops a run.
func (d *DocumentModelSettings) Validate() error {
	if d == nil || !d.Enabled {
		return nil
	}
	if !slices.Contains(DocumentModelProviders, strings.ToLower(strings.TrimSpace(d.Provider))) {
		return fmt.Errorf("options.ai.documents.provider must be one of %s", strings.Join(DocumentModelProviders, ", "))
	}
	if strings.TrimSpace(d.Model) == "" {
		return fmt.Errorf("options.ai.documents.model is required when the document model is enabled")
	}
	if d.ModelTimeout != "" {
		v, err := time.ParseDuration(d.ModelTimeout)
		if err != nil || v < 5*time.Second || v > 15*time.Minute {
			return fmt.Errorf("options.ai.documents.model_timeout must be 5s..15m")
		}
	}
	if d.MaxLeads < -1 || d.MaxLeads > 10000 {
		return fmt.Errorf("options.ai.documents.max_leads must be -1 (none), 0 (adaptive) or up to 10000")
	}
	if d.ContextTokens != 0 && (d.ContextTokens < 4096 || d.ContextTokens > 262144) {
		return fmt.Errorf("options.ai.documents.context_tokens must be 0 or 4096..262144")
	}
	if d.ChunkChars != 0 && (d.ChunkChars < 2000 || d.ChunkChars > 200000) {
		return fmt.Errorf("options.ai.documents.chunk_chars must be 0 or 2000..200000")
	}
	if d.MaxTokens != 0 && (d.MaxTokens < 256 || d.MaxTokens > 32768) {
		return fmt.Errorf("options.ai.documents.max_tokens must be 0 or 256..32768")
	}
	if d.Hold != "" {
		v, err := time.ParseDuration(strings.TrimSpace(d.Hold))
		if err != nil || v < 0 || v > 2*time.Hour {
			return fmt.Errorf("options.ai.documents.hold must be 0..2h")
		}
	}
	if d.DocumentTimeout != "" {
		v, err := time.ParseDuration(strings.TrimSpace(d.DocumentTimeout))
		if err != nil || v < 0 || v > 6*time.Hour {
			return fmt.Errorf("options.ai.documents.document_timeout must be 0..6h")
		}
	}
	if d.MaxChunks < 0 || d.MaxChunks > 10000 {
		return fmt.Errorf("options.ai.documents.max_chunks must be 0 (no cap) or up to 10000")
	}
	return nil
}

// DocumentModelEnabled reports whether a document model is configured and on.
func (a *AISettings) DocumentModelEnabled() bool {
	return a != nil && a.Documents != nil && a.Documents.Enabled
}

// DocumentsShared reports whether models other than the document model may
// read its findings, which quote the documents.
func (a *AISettings) DocumentsShared() bool {
	return a.DocumentModelEnabled() && a.Documents.ShareWithAssistants
}

// ContributionsStrong reports whether assistants' contributions may be
// strong evidence (options.ai.contributions.strong_evidence).
func (a *AISettings) ContributionsStrong() bool {
	return a != nil && a.Contributions != nil && a.Contributions.StrongEvidence
}

// loadAISettings reads options.ai into AI. Unknown keys are refused, so a
// mistyped setting never silently leaves a model off or on.
func (c *Config) loadAISettings(cfg *Config) error {
	raw, ok := c.Options["ai"]
	if !ok || raw == nil {
		return nil
	}

	data, err := yaml.Marshal(raw)
	if err != nil {
		return fmt.Errorf("options.ai: %w", err)
	}

	var s AISettings
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&s); err != nil {
		return fmt.Errorf("options.ai: %w", err)
	}
	if err := s.Documents.Validate(); err != nil {
		return err
	}

	c.AI = &s
	return nil
}

// AIKeySet reports whether options.ai sets key explicitly, for a setting whose
// zero value is a real choice (guidance_rounds: 0 turns guidance off).
func (c *Config) AIKeySet(key string) bool {
	m, ok := c.Options["ai"].(map[string]interface{})
	if !ok {
		return false
	}
	_, ok = m[key]
	return ok
}

// refuseTopLevelAI stops a configuration that still has the ai section at the
// top level, where it is no longer read, so its settings are not lost
// silently.
func refuseTopLevelAI(data []byte) error {
	var top struct {
		AI any `yaml:"ai"`
	}
	if yaml.Unmarshal(data, &top) == nil && top.AI != nil {
		return errors.New("the ai section moved to options.ai: indent it under options")
	}
	return nil
}

// Attribution modes.
const (
	AttributionAuto    = "auto"
	AttributionJournal = "journal"
	AttributionOff     = "off"
)

// ResolveAISettings applies AMASS_AI_* environment overrides without
// mutating the global Amass config. Empty env strings are intentional values.
func ResolveAISettings(base AISettings, lookup func(string) (string, bool)) (AISettings, error) {
	c := base
	stringsEnv := []struct {
		key    string
		target *string
	}{
		{"AMASS_LLM_PROVIDER", &c.Provider},
		{"AMASS_LLM_ENDPOINT", &c.Endpoint},
		{"AMASS_LLM_MODEL", &c.Model},
		{"AMASS_LLM_API_KEY_ENV", &c.APIKeyEnv},
		{"AMASS_LLM_MODEL_TIMEOUT", &c.ModelTimeout},
		{"AMASS_LLM_INVESTIGATION_TIMEOUT", &c.InvestigationTimeout},
		{"AMASS_LLM_TEMPERATURE", &c.Temperature},
		{"AMASS_CLASSIFIER_MODEL", &c.ClassifierModel},
		{"AMASS_CLASSIFIER_ENDPOINT", &c.ClassifierEndpoint},
		{"AMASS_ATTRIBUTION", &c.Attribution},
		{"AMASS_REVIEW_JOURNAL", &c.Journal},
	}
	for _, pair := range stringsEnv {
		if value, ok := lookup(pair.key); ok {
			*pair.target = value
		}
	}

	bools := []struct {
		key    string
		target *bool
	}{
		{"AMASS_LLM_ALLOW_HTTP", &c.AllowHTTP},
		{"AMASS_CLASSIFIER_REVIEW", &c.ClassifierReview},
		{"AMASS_LLM_THINK", &c.Think},
		{"AMASS_AI_CLASSIFIER_APPLIES", &c.ClassifierApplies},
	}
	for _, pair := range bools {
		if raw, ok := lookup(pair.key); ok {
			value, err := strconv.ParseBool(strings.TrimSpace(raw))
			if err != nil {
				return c, fmt.Errorf("%s: invalid boolean", pair.key)
			}

			*pair.target = value
		}
	}

	if raw, ok := lookup("AMASS_AI_ANNOUNCE_DECISIONS"); ok {
		value, err := strconv.ParseBool(strings.TrimSpace(raw))
		if err != nil {
			return c, fmt.Errorf("AMASS_AI_ANNOUNCE_DECISIONS: invalid boolean")
		}
		c.AnnounceDecisions = &value
	}

	ints := []struct {
		key    string
		target *int
	}{
		{"AMASS_LLM_DEPTH", &c.MaxDepth},
		{"AMASS_LLM_MAX_MATCHES", &c.MaxMatches},
		{"AMASS_LLM_MAX_PATHS_PER_ASSET", &c.MaxPathsPerAsset},
		{"AMASS_LLM_MAX_EXPANSIONS", &c.MaxExpansions},
		{"AMASS_LLM_GUIDANCE_ROUNDS", &c.GuidanceRounds},
		{"AMASS_LLM_MAX_TOKENS", &c.MaxTokens},
		{"AMASS_LLM_CONTEXT_TOKENS", &c.ContextTokens},
		{"AMASS_ATTRIBUTION_CANARY_EVERY", &c.AttributionCanaryEvery},
	}
	for _, pair := range ints {
		if raw, ok := lookup(pair.key); ok {
			value, err := strconv.Atoi(strings.TrimSpace(raw))
			if err != nil || value < 0 {
				return c, fmt.Errorf("%s: invalid nonnegative integer", pair.key)
			}

			*pair.target = value
		}
	}
	switch strings.ToLower(strings.TrimSpace(c.Attribution)) {
	case "", AttributionAuto, AttributionJournal, AttributionOff:
	default:
		return c, fmt.Errorf("attribution must be auto, journal or off")
	}
	if c.ModelTimeout != "" {
		v, err := time.ParseDuration(c.ModelTimeout)
		if err != nil || v < 5*time.Second || v > 15*time.Minute {
			return c, fmt.Errorf("model timeout must be 5s..15m")
		}
	}
	if c.InvestigationTimeout != "" {
		v, err := time.ParseDuration(c.InvestigationTimeout)
		if err != nil || v < 5*time.Second || v > 30*time.Minute {
			return c, fmt.Errorf("investigation timeout must be 5s..30m")
		}
	}
	if c.MaxPathsPerAsset > 8 {
		return c, fmt.Errorf("AI max_paths_per_asset must be 0..8")
	}
	if c.GuidanceRounds > 3 {
		return c, fmt.Errorf("AI guidance_rounds must be 0..3")
	}
	if c.AttributionCanaryEvery < 0 || c.AttributionCanaryEvery > 1000 {
		return c, fmt.Errorf("AI attribution_canary_every must be 0..1000")
	}
	if c.ContextTokens != 0 && (c.ContextTokens < 2048 || c.ContextTokens > 262144) {
		return c, fmt.Errorf("AI context_tokens must be 0 or 2048..262144")
	}
	if c.MaxTokens > 128000 {
		return c, fmt.Errorf("AI max_tokens must be 0..128000")
	}
	if _, err := ParseAITemperature(c.Temperature); err != nil {
		return c, err
	}
	if err := c.Documents.Validate(); err != nil {
		return c, err
	}

	return c, nil
}

// ParseAITemperature returns nil for an empty value (provider default) or the
// parsed temperature, which must be between 0 and 2.
func ParseAITemperature(raw string) (*float64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	v, err := strconv.ParseFloat(raw, 64)
	if err != nil || v < 0 || v > 2 {
		return nil, fmt.Errorf("AI temperature must be a number from 0 to 2")
	}

	return &v, nil
}
