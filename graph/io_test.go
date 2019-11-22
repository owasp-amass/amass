package graph

import (
	"testing"

	"github.com/OWASP/Amass/v3/graph/db"
)

func TestIO(t *testing.T) {
	g := NewGraph(db.NewCayleyGraphMemory())

	for _, tt := range graphTest {
		g.InsertNodeIfNotExist(tt.UUID, tt.ID)
		t.Run("Testing GetOutput...", func(t *testing.T) {

			got := g.GetOutput(tt.UUID)
			if got != nil {
				t.Errorf("Failed to get output.\nOutput:%v", got)
			}

		})
	}

}
