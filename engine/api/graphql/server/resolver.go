package server

// This file will not be regenerated automatically.
//
// It serves as dependency injection for your app, add any dependencies you require here.

import (
	"log/slog"

	et "github.com/owasp-amass/amass/v4/engine/types"
)

type Resolver struct {
	Log        *slog.Logger
	Manager    et.SessionManager
	Dispatcher et.Dispatcher
}
