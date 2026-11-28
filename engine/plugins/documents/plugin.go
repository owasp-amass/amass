// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package documents retrieves the documents (PDF, Office) that stored URLs
// name and records each as a File with its media type, size, content hash
// and the metadata the document carries (Unit 11). It is not a data source of
// its own: it reads URLs any source found. In passive mode a document is read
// from the Wayback Machine's stored copy, so the target is never contacted;
// in active mode it is fetched from the target's own URL.
package documents

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/archive"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/docmeta"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamfile "github.com/owasp-amass/open-asset-model/file"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamurl "github.com/owasp-amass/open-asset-model/url"
	"golang.org/x/time/rate"
)

// The metadata properties a File carries; each holds one value as the
// document states it.
const (
	PropTitle          = "doc_title"
	PropAuthor         = "doc_author"
	PropLastModifiedBy = "doc_last_modified_by"
	PropCreatorTool    = "doc_creator_tool"
	PropProducer       = "doc_producer"
	PropCompany        = "doc_company"
	PropCreated        = "doc_created"
	PropModified       = "doc_modified"
	PropUsername       = "doc_username"
	// PropRetrievedFrom is where the bytes were read: the archive capture URL
	// in passive mode, or the document's own URL in active mode.
	PropRetrievedFrom = "doc_retrieved_from"
)

// FingerprintType is the Identifier id_type of a File's content hash.
const FingerprintType = "file_sha256"

// errTooLarge is returned when a document is longer than the catalog allows.
var errTooLarge = errors.New("document larger than max_bytes")

type documents struct {
	name string
	log  *slog.Logger
	// ArchiveURL is the Wayback Machine's capture prefix; a capture is read
	// from ArchiveURL + <timestamp> + "id_/" + <url>, the raw bytes as
	// archived, without the archive's page around them.
	ArchiveURL string
	archive    *rate.Limiter
	direct     *rate.Limiter
	source     *et.Source

	mu   sync.Mutex
	runs map[string]*runState
}

func NewDocuments() et.Plugin {
	return &documents{
		name:       "Documents",
		ArchiveURL: "https://web.archive.org/web/",
		archive:    rate.NewLimiter(rate.Every(5*time.Second), 1),
		direct:     rate.NewLimiter(rate.Every(time.Second), 1),
		source: &et.Source{
			Name:       "Documents",
			Confidence: 90,
		},
	}
}

func (d *documents) Name() string {
	return d.name
}

func (d *documents) Start(r et.Registry) error {
	d.log = r.Log().WithGroup("plugin").With("name", d.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       d,
		Name:         d.name + "-Handler",
		Position:     20,
		MaxInstances: 2,
		Transforms: []string{string(oam.File), string(oam.Identifier), string(oam.Person),
			string(oam.Organization), string(oam.Product), string(oam.ProductRelease), string(oam.FQDN),
			string(oam.URL), string(oam.IPAddress), string(oam.Phone), string(oam.Account)},
		EventType: oam.URL,
		Callback:  d.check,
	}); err != nil {
		return err
	}
	// documents earlier runs left unread are handed back when their host
	// comes up again
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       d,
		Name:         d.name + "-Backlog-Handler",
		Position:     30,
		MaxInstances: 1,
		Transforms:   []string{string(oam.URL)},
		EventType:    oam.FQDN,
		Callback:     d.backlog,
	}); err != nil {
		return err
	}

	d.log.Info("Plugin started")
	return nil
}

func (d *documents) Stop() {
	d.log.Info("Plugin stopped")
}

func (d *documents) check(e *et.Event) error {
	u, ok := e.Entity.Asset.(*oamurl.URL)
	if !ok {
		return errors.New("failed to extract the URL asset")
	}

	rules := semantics.Documents()
	dt, ok := rules.DocumentFor(u.Path)
	if !ok || !inScope(e, u.Host) {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.URL), string(oam.File), d.name)
	if err != nil {
		return err
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, d.source, since) {
		return nil
	}
	// a document stored within the URL->File ttl is not fetched again, so
	// each run reaches documents not yet read
	if storedSince(e, e.Entity, since) {
		support.MarkAssetMonitored(e.Session, e.Entity, d.source)
		return nil
	}
	// a document left for a later run is not marked, so that run fetches it
	if why := d.admit(e, e.Entity.Asset.Key(), u.Host, rules.MaxPerRun); why != "" {
		e.Session.Log().Debug("document left for a later run", "url", u.Raw, "why", why,
			slog.Group("plugin", "name", d.name, "handler", d.name+"-Handler"))
		return nil
	}
	support.MarkAssetMonitored(e.Session, e.Entity, d.source)

	from, data, err := d.retrieve(e, u, dt, rules.MaxBytes)
	if err != nil {
		e.Session.Log().Info("document not retrieved", "url", u.Raw, "from", from, "error", err.Error(),
			slog.Group("plugin", "name", d.name, "handler", d.name+"-Handler"))
		return nil
	}

	d.store(e, e.Entity, u, dt, from, data)
	return nil
}

// errNotDocument is returned when what came back is not the document, such as
// the "page not found" HTML a site serves with a 200 status.
var errNotDocument = errors.New("the content is not the document")

// retrieve reads the document. In passive mode it reads the archive's copy.
// In active mode it fetches the document's own URL and, when that fails or
// returns something that is not the document (the page was removed and the
// site answers with an HTML page), the archive's copy: an archived URL often
// names a document the site no longer serves. It returns where the bytes came
// from.
func (d *documents) retrieve(e *et.Event, u *oamurl.URL, dt semantics.DocumentType, max int64) (string, []byte, error) {
	if e.Session.Config().Active {
		live := liveURL(u)
		data, err := d.fetchDirect(e, u, live, max)
		if err == nil && looksLike(dt.Format, data) {
			return live, data, nil
		}
		if errors.Is(err, errTooLarge) {
			return live, nil, err
		}
	}

	capture := d.captureURL(e, u)
	data, err := d.fetchArchive(e, capture, max)
	if err != nil {
		return capture, nil, err
	}
	if !looksLike(dt.Format, data) {
		return capture, nil, fmt.Errorf("%w (%s expected)", errNotDocument, dt.Format)
	}
	return capture, data, nil
}

// liveURL is the URL to fetch: the stored URL without its scheme's default
// port. Archives keep URLs as crawled ("http://host:80/a.pdf"), and some
// sites redirect such a URL to https on port 80, which cannot answer.
func liveURL(u *oamurl.URL) string {
	raw := u.Raw
	for _, def := range []struct{ scheme, port string }{{"http", ":80"}, {"https", ":443"}} {
		prefix := def.scheme + "://" + u.Host + def.port
		if !strings.HasPrefix(strings.ToLower(raw), strings.ToLower(prefix)) {
			continue
		}
		// the port ends where the path, query or fragment begins, so ":80"
		// is not taken from ":8080"
		if rest := raw[len(prefix):]; rest == "" || strings.ContainsRune("/?#", rune(rest[0])) {
			raw = def.scheme + "://" + u.Host + rest
		}
	}
	return raw
}

// inScope reports whether the URL's host is in the session's scope; only
// in-scope documents are retrieved.
func inScope(e *et.Event, host string) bool {
	if host == "" {
		return false
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		_, conf := e.Session.Scope().IsAssetInScope(&oamnet.IPAddress{Address: addr}, 0)
		return conf > 0
	}
	_, conf := e.Session.Scope().IsAssetInScope(&oamdns.FQDN{Name: host}, 0)
	return conf > 0
}

// captureURL is the Wayback raw-capture URL for u: at the capture date a web
// archive recorded for the URL, or, without one, the most recent capture
// (a partial timestamp is read as the capture nearest to it).
func (d *documents) captureURL(e *et.Event, u *oamurl.URL) string {
	ts := "2"
	if first := firstSeen(e, e.Entity); !first.IsZero() {
		ts = first.UTC().Format("20060102150405")
	}
	return d.ArchiveURL + ts + "id_/" + u.Raw
}

// firstSeen returns the URL's archive_first_seen property, or the zero time.
func firstSeen(e *et.Event, ent *dbt.Entity) time.Time {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
	defer cancel()

	tags, err := e.Session.DB().FindEntityTags(ctx, ent, time.Time{}, archive.PropArchiveFirstSeen)
	if err != nil {
		return time.Time{}
	}
	for _, tag := range tags {
		if p, ok := tag.Property.(*oamgen.SimpleProperty); ok {
			if t, err := time.Parse(time.RFC3339, p.PropertyValue); err == nil {
				return t
			}
		}
	}
	return time.Time{}
}

func (d *documents) fetchArchive(e *et.Event, capture string, max int64) ([]byte, error) {
	_ = support.WaitLimit(e.Session.Ctx(), d.archive)
	return fetch(e, e.Session.Clients().General, capture, max)
}

func (d *documents) fetchDirect(e *et.Event, u *oamurl.URL, live string, max int64) ([]byte, error) {
	if err := support.PaceProbe(e, u.Host); err != nil {
		return nil, err
	}
	_ = support.WaitLimit(e.Session.Ctx(), d.direct)
	return fetch(e, e.Session.Clients().Probe, live, max)
}

// fetch GETs u and returns at most max bytes of its body: a longer document
// (by its Content-Length or by what it sends) is errTooLarge, and only a 200
// answer is read.
func fetch(e *et.Event, client *http.Client, u string, max int64) ([]byte, error) {
	e.Session.NetSem().Acquire()
	defer e.Session.NetSem().Release()

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 2*time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", amasshttp.UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	if resp.ContentLength > max {
		return nil, errTooLarge
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, errTooLarge
	}
	return data, nil
}

// looksLike reports whether data starts the way a document of the format
// does: "%PDF-" for PDF, a ZIP local file header for OOXML.
func looksLike(format string, data []byte) bool {
	switch format {
	case docmeta.FormatPDF:
		return bytes.HasPrefix(data, []byte("%PDF-"))
	case docmeta.FormatOOXML:
		return bytes.HasPrefix(data, []byte("PK\x03\x04"))
	}
	return false
}

// store records the document as a File linked from its URL, its content hash
// as a fingerprint and the metadata it carries as properties, then the leads
// its metadata and content give (leads.go). Everything stored is what the
// document states (principle 10); nothing about ownership is concluded here.
func (d *documents) store(e *et.Event, urlent *dbt.Entity, u *oamurl.URL, dt semantics.DocumentType,
	from string, data []byte) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	file := &oamfile.File{
		URL:  u.Raw,
		Name: path.Base(u.Path),
		Type: dt.MediaType,
		Size: int64(len(data)),
	}
	fent, err := e.Session.DB().CreateAsset(ctx, file)
	if err != nil || fent == nil {
		return
	}
	support.AddSource(ctx, e.Session, fent, d.source)

	_, _ = support.Relate(ctx, e.Session, urlent, &oamgen.SimpleRelation{Name: "file"}, fent, d.source)

	sum := sha256.Sum256(data)
	_ = support.StoreFingerprint(e, fent, d.source, FingerprintType, hex.EncodeToString(sum[:]))
	d.property(ctx, e, fent, PropRetrievedFrom, from)

	meta, err := docmeta.Extract(dt.Format, data)
	if err != nil {
		e.Session.Log().Info("document metadata not read", "url", u.Raw, "error", err.Error(),
			slog.Group("plugin", "name", d.name, "handler", d.name+"-Handler"))
	}
	for _, p := range []struct{ name, value string }{
		{PropTitle, meta.Title},
		{PropAuthor, meta.Author},
		{PropLastModifiedBy, meta.LastModifiedBy},
		{PropCreatorTool, meta.Creator},
		{PropProducer, meta.Producer},
		{PropCompany, meta.Company},
		{PropCreated, meta.Created},
		{PropModified, meta.Modified},
	} {
		d.property(ctx, e, fent, p.name, p.value)
	}
	for _, name := range meta.Usernames {
		d.property(ctx, e, fent, PropUsername, name)
	}

	e.Session.Log().Info("document stored", "url", u.Raw, "type", dt.MediaType, "size", len(data),
		slog.Group("plugin", "name", d.name, "handler", d.name+"-Handler"))
	d.dispatch(e, fent, fmt.Sprintf("%s:%s", fent.Asset.AssetType(), fent.Asset.Key()))

	// everything the document names that maps to an OAM type is linked from
	// the File and handed to the pipeline as a lead
	var n leads
	authors, logins := d.metadataLeads(e, fent, meta, &n)
	// content first, so an email address the document itself holds is
	// observed before a username is compared with it
	usernames := d.contentLeads(e, fent, u, dt, data, &n)
	accounts := append(append(slices.Clone(meta.Usernames), logins...), usernames...)
	d.accountLeads(e, fent, u, accounts, authors, &n)
	d.imageLeads(e, fent, dt, data, &n)
	d.logLeads(e, u, n)
}

func (d *documents) property(ctx context.Context, e *et.Event, ent *dbt.Entity, name, value string) {
	if value == "" {
		return
	}
	_, _ = e.Session.DB().CreateEntityProperty(ctx, ent, &oamgen.SimpleProperty{
		PropertyName:  name,
		PropertyValue: value,
	})
}
