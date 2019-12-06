package graph

import (
	"testing"

	"github.com/OWASP/Amass/v3/graph/db"
)

var graphTest = []struct {
	Addr      string
	Source    string
	Tag       string
	FQDN      string
	EventID   string
	Name      string
	ASN       int
	ASNString string
	CIDR      string
	Desc      string
	Service   string
	ID        string
	Domain    string
}{
	{
		"testaddr",
		"testsource",
		"testtag",
		"www.owasp.org",
		"ef9f9475-34eb-465e-81eb-77c944822d0f",
		"testname",
		667,
		"667",
		"10.0.0.0/8",
		"a test description",
		"testservice.com",
		"TestID",
		"owasp.org",
	},
}

func TestNewGraph(t *testing.T) {
	got := NewGraph(db.NewCayleyGraphMemory())
	t.Run("Testing NewGraph...", func(t *testing.T) {
		if got == nil {
			t.Errorf("Database is nil")
		}
	})

	t.Run("Testing db.String...", func(t *testing.T) {
		get := got.db.String()
		expected := "Cayley Graph"

		if get != expected {
			t.Errorf("Error running String().\ngot %v\nwanted:%v", get, expected)
		}
	})

	t.Run("Testing InsertNodeIfNotExist", func(t *testing.T) {

		nodeOne, err := got.InsertNodeIfNotExist("foo", "test node")

		if err != nil {
			t.Errorf("Error inserting node:%v", err)
		}
		nodeTwo, err := got.InsertNodeIfNotExist("bar", "also node")

		if err != nil {
			t.Errorf("Error inserting node:%v", err)
		}

		t.Run("Testing InsertEdge...", func(t *testing.T) {
			testEdge := &db.Edge{
				Predicate: "testing",
				From:      nodeOne,
				To:        nodeTwo,
			}

			err := got.InsertEdge(testEdge)

			if err != nil {
				t.Errorf("Error inserting edge:%v\n", err)

			}
		})

	})
	got.Close()

}
