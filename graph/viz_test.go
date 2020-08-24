package graph

import (
	"testing"
)

func TestViz(t *testing.T) {
	g := NewGraph(NewCayleyGraphMemory())

	tt := []struct {
		fqdn    string
		addr    string
		source  string
		tag     string
		eventID string
	}{
		{fqdn: "dev.example.domain", addr: "127.0.0.1", source: "test", tag: "foo", eventID: "barbazz"},
	}

	for _, tc := range tt {
		t.Run("Testing VizData...", func(t *testing.T) {
			err := g.InsertA(tc.fqdn, tc.addr, tc.source, tc.tag, tc.eventID)

			if err != nil {
				t.Errorf("Error inserting A record.\n%v", err)
			}
			gotNode, gotEdge := g.VizData(tc.eventID)
			if gotNode == nil {
				t.Errorf("Failed to obtain node.\n%v", gotNode)
			}
			if gotEdge == nil {
				t.Errorf("Failed to obtain edge.\n%v", gotEdge)
			}

		})
	}

}
