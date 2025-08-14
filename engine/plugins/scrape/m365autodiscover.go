// Written by: <github.com/JohnEarle>
// Inspired by: <https://github.com/SecurityRiskAdvisors/letItGo>
package scrape

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/caffix/stringset"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/time/rate"
)

type m365autodiscover struct {
	name   string
	rlimit *rate.Limiter
	log    *slog.Logger
	source *et.Source
}

// Initializes the m365Autodiscover plugin
func NewM365Autodiscover() et.Plugin {
	return &m365autodiscover{
		name:   "M365Autodiscover",
		rlimit: rate.NewLimiter(rate.Every(500*time.Millisecond), 1), // 2 requests per second
		source: &et.Source{
			Name:       "M365Autodiscover",
			Confidence: 80,
		},
	}
}

// Name returns the plugin name
func (m *m365autodiscover) Name() string {
	return m.name
}

// Start registers the plugin with the Amass engine
func (m *m365autodiscover) Start(r et.Registry) error {
	m.log = r.Log().WithGroup("plugin").With("name", m.name)
	//m.log = slog.New(slog.NewTextHandler(os.Stdout, nil))

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       m,
		Name:         m.name + "-Handler",
		Transforms:   []string{string(oam.FQDN)},
		Priority:     5,
		MaxInstances: 5,
		EventType:    oam.FQDN,
		Callback:     m.check,
	}); err != nil {
		return err
	}
	m.log.Info("m365Autodiscover Plugin started")
	return nil
}

// Stop implements the Stop method required by et.Plugin
func (m *m365autodiscover) Stop() {
	m.log.Info("m365Autodiscover Plugin stopped")
}

func (m *m365autodiscover) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	// Only run the query for root domains (e.g., owasp.org) that are in scope
	eTLDPlusOne, err := publicsuffix.EffectiveTLDPlusOne(fqdn.Name)
	if err != nil || fqdn.Name != eTLDPlusOne {
		// This is a subdomain, so we don't need to query it
		m.log.Info("subdomain, so we don't need to query it")
		return nil
	}

	// Check if the FQDN is in scope
	if _, conf := e.Session.Scope().IsAssetInScope(fqdn, 0); conf == 0 {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), m.name)
	if err != nil {
		return err
	}

	var names []*dbt.Entity
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, m.source, since) {
		names = append(names, m.lookup(e, fqdn.Name, since)...)
	} else {
		names = append(names, m.query(e, fqdn.Name, m.source)...)
		support.MarkAssetMonitored(e.Session, e.Entity, m.source)
	}

	if len(names) > 0 {
		m.process(e, names)
	}
	return nil
}

func (m *m365autodiscover) query(e *et.Event, name string, source *et.Source) []*dbt.Entity {
	if e == nil || e.Session == nil {
		m.log.Info("Invalid Event Or Session")
		return nil
	}

	if err := m.rlimit.Wait(context.Background()); err != nil {
		return nil
	}

	subs := stringset.New()
	defer subs.Close()

	soapEnvelope := []byte(strings.TrimSpace(fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:ext="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
<soap:Header>
	<a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
	<a:To soap:mustUnderstand="1">https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc</a:To>
	<a:ReplyTo>
		<a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
	</a:ReplyTo>
</soap:Header>
<soap:Body>
	<GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
		<Request>
			<Domain>%s</Domain>
		</Request>
	</GetFederationInformationRequestMessage>
</soap:Body>
</soap:Envelope>`, name)))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := postSOAP(ctx, "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc", soapEnvelope)
	if err != nil {

		return nil
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	var envelope struct {
		XMLName xml.Name `xml:"Envelope"`
		Body    struct {
			GetFederationInformationResponseMessage struct {
				Response struct {
					Domains struct {
						Domain []string `xml:"Domain"`
					} `xml:"Domains"`
				} `xml:"Response"`
			} `xml:"GetFederationInformationResponseMessage"`
		} `xml:"Body"`
	}

	if err := xml.NewDecoder(bytes.NewReader(responseBody)).Decode(&envelope); err != nil {
		return nil
	}

	for _, domain := range envelope.Body.GetFederationInformationResponseMessage.Response.Domains.Domain {
		if !strings.Contains(strings.ToLower(domain), "onmicrosoft") {
			subs.Insert(strings.ToLower(domain))
		}
	}

	if subs.Len() == 0 {
		return nil
	}

	return m.store(e, subs.Slice(), m.source)
}

func (m *m365autodiscover) store(e *et.Event, names []string, src *et.Source) []*dbt.Entity {
	// Add Domains to Scope
	for _, domain := range names {
		if e.Session.Scope().AddDomain(domain) {
			m.log.Info("m365autodiscover: Added new domain to scope", "domain", domain)
		}
	}
	entities := support.StoreFQDNsWithSource(e.Session, names, m.source, m.name, m.name+"-Handler")
	return entities
}

func (m *m365autodiscover) process(e *et.Event, assets []*dbt.Entity) {
	support.ProcessFQDNsWithSource(e, assets, m.source)
}

func (m *m365autodiscover) lookup(e *et.Event, name string, since time.Time) []*dbt.Entity {
	return support.SourceToAssetsWithinTTL(e.Session, name, string(oam.FQDN), m.source, since)
}

// postSOAP sends the SOAP request to the specified URL
func postSOAP(ctx context.Context, url string, envelope []byte) (*http.Response, error) {
	request, err := http.NewRequest("POST", url, bytes.NewReader(envelope))
	tr := &http.Transport{
		DisableCompression: true,
	}
	client := &http.Client{Transport: tr}
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "text/xml; charset=utf-8")
	request.Header.Set("SOAPAction", `"http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation"`)
	request.Header.Set("User-Agent", "AutodiscoverClient")
	return client.Do(request)
}
