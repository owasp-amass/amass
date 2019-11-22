package graph

import (
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/OWASP/Amass/v3/graph/db"
)

func TestEvent(t *testing.T) {
	need := time.Now()
	g := NewGraph(db.NewCayleyGraphMemory())

	for _, tt := range graphTest {
		nodeOne, err := g.InsertNodeIfNotExist(tt.ID, "test node")
		if err != nil {
			t.Errorf("Error creating node during TestEvent:%v\n", err)
			t.Run("Testing InsertEvent...", func(t *testing.T) {
				got, err := g.InsertEvent(tt.EventID)
				if err != nil {
					t.Errorf("Error inserting event:%v\n", err)
				}
				if got != tt.EventID {
					t.Errorf("Inserting new event failed.\n Got:%v\nWant:%v\n", got, tt.EventID)
				}
			})

			t.Run("Testing AddNodeToEvent...", func(t *testing.T) {
				err := g.AddNodeToEvent(nodeOne, tt.Source, tt.Tag, tt.EventID)
				if err != nil {
					t.Errorf("Error adding node to event:%v\n", err)
				}
			})

			t.Run("Testing EventList...", func(t *testing.T) {
				var want []string
				got := g.EventList()

				want = append(want, tt.EventID)
				if !reflect.DeepEqual(got, want) {
					t.Errorf("EventList expected %v\nGot:%v\n", got, want)
				}
			})

			t.Run("Testing EventDomains...", func(t *testing.T) {
				var want []string
				got := g.EventDomains(tt.UUID)
				want = append(want, tt.FQDN, tt.Service)
				sort.Strings(got)
				sort.Strings(want)
				for i, get := range got {
					if want[i] != get {
						t.Errorf("Error testing event domains.\nWant:%v\nGot:%v\n", want, got)
					}
				}

			})

			t.Run("Testing EventDateRange...", func(t *testing.T) {

				want, err := time.Parse(time.RFC3339, need.Format(time.RFC3339))
				start, finish := g.EventDateRange(tt.EventID)

				if err != nil {
					t.Errorf("Error getting current time.\n%v\n", err)
				}

				if want.After(finish) {
					t.Errorf("Finish time is after current time.\nFinish:%v\nNow:%v\n", finish, want)
				}

				if want.Before(start) {
					t.Errorf("Current time is before start time.\nStart:%v\nNow:%v\n", start, want)
				}

			})
		}
	}
	g.Close()
}
