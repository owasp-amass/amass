// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package server Amass Engine API.
//
// @title           Amass Engine API (v1)
// @version         1.0
// @description     HTTP API for managing Amass Engine sessions and submitting Open Asset Model (OAM) assets.
// @description     Create a session with an engine config, query session stats/scope, and ingest typed OAM assets (single or bulk).
// @description		Includes a WebSocket endpoint for streaming session logs.
// @termsOfService  https://owasp.org/www-project-amass/
//
// @contact.name    OWASP Amass Project
// @contact.url     https://github.com/owasp-amass/amass
//
// @license.name    Apache 2.0
// @license.url     https://www.apache.org/licenses/LICENSE-2.0
//
// @BasePath        /api/v1
//
// @tag.name        system
// @tag.description System endpoints (health, etc.)
// @tag.name        sessions
// @tag.description Create, list, inspect, and terminate engine sessions.
// @tag.name        scope
// @tag.description Read-only access to the scoped assets loaded into a session.
// @tag.name        assets
// @tag.description Submit typed OAM assets to a session (single or bulk).
// @tag.name        ws
// @tag.description WebSocket endpoints (e.g., session log streaming).
package v1
