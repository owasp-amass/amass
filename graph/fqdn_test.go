package graph

import (
	"testing"

	"github.com/OWASP/Amass/v3/graph/db"
)

func TestFQDN(t *testing.T) {
	g := NewGraph(db.NewCayleyGraphMemory())
	for _, tt := range graphTest {
		t.Run("Testing InsertFQDN...", func(t *testing.T) {

			got, err := g.InsertFQDN(tt.FQDN, tt.Source, tt.Tag, tt.EventID)

			if err != nil {
				t.Errorf("Failed inserting FQDN:\n%v", err)
			}

			if got != tt.FQDN {
				t.Errorf("Error expecting FQDN.\nGot:%v\nWant:%v\n", got, tt.FQDN)
			}

		})

		t.Run("Testing InsertCNAME...", func(t *testing.T) {
			err := g.InsertCNAME(tt.FQDN, tt.FQDN, tt.Source, tt.Tag, tt.EventID)

			if err != nil {
				t.Errorf("Failed inserting CNAME.\n%v", err)
			}
		})

		t.Run("Testing IsCNAMENode...", func(t *testing.T) {
			got := g.IsCNAMENode(tt.FQDN)

			if got != true {
				t.Errorf("Failed to obtain CNAME from node: %v\n", got)
			}
		})

		t.Run("Testing InsertPTR...", func(t *testing.T) {
			got := g.InsertPTR(tt.FQDN, tt.FQDN, tt.Source, tt.Tag, tt.EventID)
			if got != nil {
				t.Errorf("Failed to InsertPTR. \n%v\n", got)
			}
		})

		t.Run("Testing IsPTRNode...", func(t *testing.T) {
			got := g.IsPTRNode(tt.FQDN)
			if got != true {
				t.Errorf("Failed to find PTRNode.\n%v:%v\n", tt.FQDN, got)
			}
		})

		t.Run("Testing InsertSRV...", func(t *testing.T) {
			got := g.InsertSRV(tt.FQDN, tt.Service, tt.FQDN, tt.Source, tt.Tag, tt.EventID)
			if got != nil {
				t.Errorf("Failed inserting service into database.\n%v\n", got)
			}
		})

		t.Run("Testing InsertNS...", func(t *testing.T) {
			got := g.InsertNS(tt.FQDN, tt.FQDN, tt.Source, tt.Tag, tt.EventID)

			if got != nil {
				t.Errorf("Failed inserting NS record.\n%v\n", got)
			}
		})

		t.Run("Testing IsNSNode...", func(t *testing.T) {
			got := g.IsNSNode(tt.FQDN)
			if got == false {
				t.Errorf("Failed to locate NS node.\n%v\n", got)
			}
		})

		t.Run("Testing InsertMX...", func(t *testing.T) {
			got := g.InsertMX(tt.FQDN, tt.FQDN, tt.Source, tt.Tag, tt.EventID)
			if got != nil {
				t.Errorf("Failure to insert MX record.\n%v\n", got)
			}
		})

		t.Run("Testing IsMXNode...", func(t *testing.T) {
			got := g.IsMXNode(tt.FQDN)
			if got != true {
				t.Errorf("Failed to locate MX node.")
			}
		})

		t.Run("Testing IsRootDomainNode...", func(t *testing.T) {
			got := g.IsRootDomainNode("owasp.org")
			if got != true {
				t.Errorf("Failed to locate root domain node.")
			}
		})

		t.Run("Testing IsTLDNode...", func(t *testing.T) {
			got := g.IsTLDNode("org")
			if got != true {
				t.Errorf("Failed to locate TLD node.")
			}
		})
	}

	g.Close()
}
