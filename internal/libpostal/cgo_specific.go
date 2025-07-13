//go:build cgo
// +build cgo

// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package libpostal

/*
#cgo pkg-config: libpostal
#include <libpostal/libpostal.h>
#include <stdlib.h>

*/
import "C"

import (
	"errors"
	"sync"
	"unicode/utf8"
	"unsafe"
)

type ParserOptions struct {
	Language string
	Country  string
}

var (
	postalLock           sync.Mutex
	postalLibAvailable   bool
	parserDefaultOptions = getDefaultParserOptions()
)

func init() {
	if bool(C.libpostal_setup()) && bool(C.libpostal_setup_parser()) {
		postalLibAvailable = true
	}
}

func getDefaultParserOptions() ParserOptions {
	return ParserOptions{
		Language: "",
		Country:  "",
	}
}

func ParseAddress(address string) ([]ParsedComponent, error) {
	return ParseAddressOptions(address, parserDefaultOptions)
}

func ParseAddressOptions(address string, options ParserOptions) ([]ParsedComponent, error) {
	if !postalLibAvailable {
		return nil, errors.New(ErrPostalLibNotAvailable)
	}

	if !utf8.ValidString(address) {
		return nil, errors.New("address is not a valid UTF-8 string")
	}

	postalLock.Lock()
	defer postalLock.Unlock()

	cAddress := C.CString(address)
	defer C.free(unsafe.Pointer(cAddress))

	cOptions := C.libpostal_get_address_parser_default_options()
	if options.Language != "" {
		cLanguage := C.CString(options.Language)
		defer C.free(unsafe.Pointer(cLanguage))

		cOptions.language = cLanguage
	}

	if options.Country != "" {
		cCountry := C.CString(options.Country)
		defer C.free(unsafe.Pointer(cCountry))

		cOptions.country = cCountry
	}

	cAddressParserResponsePtr := C.libpostal_parse_address(cAddress, cOptions)

	if cAddressParserResponsePtr == nil {
		return nil, errors.New("failed to parse address")
	}

	cAddressParserResponse := *cAddressParserResponsePtr

	cNumComponents := cAddressParserResponse.num_components
	cComponents := cAddressParserResponse.components
	cLabels := cAddressParserResponse.labels

	numComponents := uint64(cNumComponents)

	parsedComponents := make([]ParsedComponent, numComponents)

	// Accessing a C array
	cComponentsPtr := (*[1 << 30](*C.char))(unsafe.Pointer(cComponents))[:numComponents:numComponents]
	cLabelsPtr := (*[1 << 30](*C.char))(unsafe.Pointer(cLabels))[:numComponents:numComponents]

	var i uint64
	for i = 0; i < numComponents; i++ {
		parsedComponents[i] = ParsedComponent{
			Label: C.GoString(cLabelsPtr[i]),
			Value: C.GoString(cComponentsPtr[i]),
		}
	}

	C.libpostal_address_parser_response_destroy(cAddressParserResponsePtr)

	return parsedComponents, nil
}
