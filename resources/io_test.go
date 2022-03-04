package resources

import (
	"fmt"
	"testing"
)

func TestGetIP2ASNData(t *testing.T) {
	_, err := GetIP2ASNData()
	if fmt.Sprintf("%v", err) != "<nil>" {
		t.Errorf("parseIPs.parseRange() error = %v, wantErr <nil>", err)

	}
}
func TestGetDefaultScripts(t *testing.T) {
	_, err := GetDefaultScripts()
	if fmt.Sprintf("%v", err) != "<nil>" {
		t.Errorf("parseIPs.parseRange() error = %v, wantErr <nil>", err)

	}
}

