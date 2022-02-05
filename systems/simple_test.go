package systems


import "testing"

func TestGetMemoryUsage(t *testing.T) {
      c := new(LocalSystem)
    Memory := c.GetMemoryUsage()
    if ((Memory % 2) != 0) {
       t.Errorf(" Memory was not allocated, got: %d", Memory)
    }
}
