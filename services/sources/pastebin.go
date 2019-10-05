package sources

import (
	"time"
	
	"github.com/OWASP/Amass/services"
)

// Pastebin is the Service that handles access to the CertSpotter data source.
type Pastebin struct {
	services.BaseService

	SourceType string
	RateLimit  time.Duration
}