package graph

import (
	"testing"

	"github.com/OWASP/Amass/v3/graph/db"
)

func TestSource(t *testing.T) {
	g := NewGraph(db.NewCayleyGraphMemory())

	for _, tt := range graphTest {
		t.Run("Testing InsertSource...", func(t *testing.T) {
			got, err := g.InsertSource(tt.Source, tt.Tag)
			if err != nil {
				t.Errorf("Failed to insert source.\n%v\n", err)

			}
			if got != tt.Source {
				t.Errorf("Expected:%v\nGot:%v", tt.Source, got)
			}

		})

		t.Run("Testing SourceTag...", func(t *testing.T) {
			got := g.SourceTag(tt.Source)
			if got != tt.Tag {
				t.Errorf("Expecting to return tag:%v\nGot:%v", tt.Tag, got)
			}
		})
	}
}
