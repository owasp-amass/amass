package systems
import "testing"

func TestGetMemoryUsage(t *testing.T){
    c := new(LocalSystem)
    m := c.GetMemoryUsage()
    if ((m % 2) != 0){
       t.Errorf("Memory was not allocated, got: %d",m)
    }
}
