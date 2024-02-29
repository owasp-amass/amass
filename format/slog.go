// Copyright © by Jeff Foley 2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package format

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"
)

func JSONLogToRecord(logstr string) (slog.Record, error) {
	j := make(map[string]interface{})
	// unmarshal the log message sent from the engine session
	if err := json.Unmarshal([]byte(logstr), &j); err != nil {
		return slog.Record{}, errors.New("Failed to unmarchal the JSON")
	}

	var ltime time.Time
	// cheating right now by replacing the time
	if _, found := j[slog.TimeKey]; found {
		ltime = time.Now()
	}
	delete(j, slog.TimeKey)

	var level slog.Level
	// extract the log level for the new record
	if val, found := j[slog.LevelKey]; !found {
		return slog.Record{}, errors.New("Failed to find the level key")
	} else if str, ok := val.(string); !ok {
		return slog.Record{}, errors.New("Failed to cast the level value")
	} else if level.UnmarshalText([]byte(str)) != nil {
		return slog.Record{}, errors.New("Failed to unmarshal the level text")
	}
	delete(j, slog.LevelKey)

	var msg string
	// extract the log message for the new record
	if val, found := j[slog.MessageKey]; !found {
		return slog.Record{}, errors.New("Failed to find the msg key")
	} else if str, ok := val.(string); !ok {
		return slog.Record{}, errors.New("Failed to cast the msg value")
	} else {
		msg = str
	}
	delete(j, slog.MessageKey)

	var pc uintptr
	record := slog.NewRecord(ltime, level, msg, pc)
	record.AddAttrs(jsonToAttrs(j)...)
	return record, nil
}

func jsonToAttrs(jmap map[string]interface{}) []slog.Attr {
	var attrs []slog.Attr

	for k, v := range jmap {
		switch val := v.(type) {
		case bool:
			attrs = append(attrs, slog.Bool(k, val))
		case float64:
			attrs = append(attrs, jsonNumberToAttr(k, val))
		case string:
			attrs = append(attrs, slog.String(k, val))
		case map[string]interface{}:
			if a := jsonToAttrs(val); len(a) > 0 {
				attrs = append(attrs, slog.Attr{
					Key:   k,
					Value: slog.GroupValue(a...),
				})
			}
		}
	}
	return attrs
}

func jsonNumberToAttr(key string, num float64) slog.Attr {
	if s := fmt.Sprintf("%f", num); s != "" {
		if i, err := strconv.ParseInt(s, 10, 64); err == nil {
			return slog.Int64(key, i)
		}
	}
	return slog.Float64(key, num)
}
