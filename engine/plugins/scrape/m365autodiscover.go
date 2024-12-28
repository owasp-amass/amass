// Written by: <github.com/JohnEarle>
// Inspired by: <https://github.com/SecurityRiskAdvisors/letItGo>
package scrape

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/caffix/stringset"
	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/property"
	"github.com/owasp-amass/open-asset-model/relation"
	"go.uber.org/ratelimit"
)

type m365autodiscover struct {
	name   string
	rlimit ratelimit.Limiter
	log    *slog.Logger
	source *et.Source
}

// Initializes the m365Autodiscover plugin
func NewM365Autodiscover() et.Plugin {
	return &m365autodiscover{
		name:   "M365Autodiscover",
		rlimit: ratelimit.New(2, ratelimit.WithoutSlack),
		source: &et.Source{
			Name:       "M365Autodiscover",
			Confidence: 90,
		},
	}
}

// Name returns the plugin name
func (m *m365autodiscover) Name() string {
	return m.name
}

// Start registers the plugin with the Amass engine
func (m *m365autodiscover) Start(r et.Registry) error {
	m.log = slog.New(slog.NewTextHandler(os.Stdout, nil)).WithGroup("plugin").With("name", m.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       m,
		Name:         m.name + "-Handler",
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
	entities, err := m.query(e, e.Entity.Asset.(*domain.FQDN).Name, m.source)
	if err != nil {
		return nil
	}
	support.MarkAssetMonitored(e.Session, e.Entity, m.source)

	if len(entities) > 0 {
		m.process(e, entities, m.source)
	}
	return nil
}

func (m *m365autodiscover) query(e *et.Event, name string, source *et.Source) ([]*dbt.Entity, error) {
	if e == nil || e.Session == nil {
		m.log.Info("Invalid Event Or Session")
		return nil, fmt.Errorf("invalid event or session")
	}

	m.rlimit.Take()

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
		return nil, err
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
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
		return nil, err
	}

	for _, domain := range envelope.Body.GetFederationInformationResponseMessage.Response.Domains.Domain {
		subs.Insert(strings.ToLower(domain))
	}

	if subs.Len() == 0 {
		return nil, fmt.Errorf("no valid domains found")
	}

	return m.store(e, subs.Slice(), m.source), nil
}

func (m *m365autodiscover) store(e *et.Event, names []string, src *et.Source) []*dbt.Entity {
	m.log.Info("store function called", "names", names)
	entities := support.StoreFQDNsWithSource(e.Session, names, m.source, m.name, m.name+"-Handler")

	// Create edges between the event entity and the new FQDNs
	for _, entity := range entities {
		if entity == nil {
			e.Session.Log().Error("Entity is nil")
			continue
		}
		if e.Entity == nil {
			e.Session.Log().Error("Event entity is nil")
			continue
		}
		// REQUIRE A MORE RELEVANT RELATIONSHIP TYPE -- Pending changes to OAM model
		edge, err := e.Session.Cache().CreateEdge(&dbt.Edge{
			Relation:   &relation.SimpleRelation{Name: "node"},
			FromEntity: e.Entity,
			ToEntity:   entity,
		})
		if err != nil {
			m.log.Error("Failed to create edge", "error", err)
			continue
		}
		if edge == nil {
			m.log.Error("Edge is nil")
			continue
		}

		// Log the edge details
		m.log.Info("m365Autodiscover Edge created", "from", e.Entity.ID, "to", entity.ID, "relation", "associated_with")

		_, err = e.Session.Cache().CreateEdgeProperty(edge, &property.SourceProperty{
			Source:     m.source.Name,
			Confidence: m.source.Confidence,
		})
		if err != nil {
			m.log.Error("Failed to create edge property", "error", err)
		}
	}

	return entities
}

func (m *m365autodiscover) process(e *et.Event, assets []*dbt.Entity, source *et.Source) {
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
