package graph

import (
	"testing"

	"github.com/OWASP/Amass/v3/graph/db"
)

func TestAddress(t *testing.T) {
	g := NewGraph(db.NewCayleyGraphMemory())
	for _, tt := range graphTest {
		t.Run("Testing InsertAddress...", func(t *testing.T) {

			got, err := g.InsertAddress(tt.Addr, tt.Source, tt.Tag, tt.EventID)

			if err != nil {
				t.Errorf("Error inserting address:%v\n", err)
			}

			if got != tt.Addr {
				t.Errorf("Name of node was not returned properly.\nExpected:%v\nGot:%v\n", tt.Addr, got)
			}
		})

		t.Run("Testing InsertA...", func(t *testing.T) {

			err := g.InsertA(tt.FQDN, tt.Addr, tt.Source, tt.Tag, tt.EventID)
			if err != nil {
				t.Errorf("Error inserting fqdn:%v\n", err)
			}
		})

		t.Run("Testing InsertAAAA...", func(t *testing.T) {

			err := g.InsertAAAA(tt.FQDN, tt.Addr, tt.Source, tt.Tag, tt.EventID)

			if err != nil {
				t.Errorf("Error inserting AAAA record: %v\n", err)
			}
		})
	}

	g.Close()
}
