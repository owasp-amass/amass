package graph

import (
	"testing"

	"github.com/OWASP/Amass/v3/graph/db"
)

func VizTest(t *testing.T) {
	g := NewGraph(db.NewCayleyGraphMemory())

	for _, tt := range graphTest {
		t.Run("Testing VizData...", func(t *testing.T) {
			err := g.InsertA(tt.FQDN, tt.Addr, tt.Source, tt.Tag, tt.EventID)

			if err != nil {
				t.Errorf("Error inserting A record.\n%v", err)
			}
			gotNode, gotEdge := g.VizData(tt.EventID)
			if gotNode == nil {
				t.Errorf("Failed to obtain node.\n%v", gotNode)
			}
			if gotEdge == nil {
				t.Errorf("Failed to obtain edge.\n%v", gotEdge)
			}

		})
	}

}
