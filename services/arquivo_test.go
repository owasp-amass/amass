package services

import (
	"testing"
)

func TestArquivo(t *testing.T) {
	if *networkTest == false {
		return
	}

	result := testDNSRequest("Arquivo")
	if result < expectedTest {
		t.Errorf("Found %d names, expected at least %d instead", result, expectedTest)
	}
}
