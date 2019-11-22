package graph

import (
	"testing"

	"github.com/OWASP/Amass/v3/graph/db"
)

func TestAS(t *testing.T) {
	g := NewGraph(db.NewCayleyGraphMemory())

	for _, tt := range graphTest {
		t.Run("Testing InsertAS...", func(t *testing.T) {

			got, err := g.InsertAS(tt.ASNString, tt.Desc, tt.Source, tt.Tag, tt.EventID)

			if err != nil {
				t.Errorf("Error inserting AS:%v\n", err)
			}
			if got != tt.ASNString {
				t.Errorf("Returned value for InsertAS is not the same as test asn string:\ngot%v\nwant:%v\n", got, tt.ASNString)
			}
		})

		t.Run("Testing InsertInfrastructure", func(t *testing.T) {

			err := g.InsertInfrastructure(tt.ASN, tt.Desc, tt.Addr, tt.CIDR, tt.Source, tt.Tag, tt.EventID)
			if err != nil {
				t.Errorf("Error inserting infrastructure:%v\n", err)
			}
		})

		t.Run("Testing ReadASDescription", func(t *testing.T) {
			got := g.ReadASDescription(tt.ASNString)

			if got != tt.Desc {
				t.Errorf("Expected:%v\nGot:%v\n", tt.Desc, got)
			}
		})
	}

	g.Close()
}
