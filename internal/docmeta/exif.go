// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package docmeta

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"strings"
	"unicode/utf16"
)

// EXIF is what an image's EXIF block says about who took or made it, with
// what, when and where. Values are as written, cleaned like the document
// metadata.
type EXIF struct {
	Make     string `json:"make,omitempty"`
	Model    string `json:"model,omitempty"`
	Software string `json:"software,omitempty"`
	// Artist is the EXIF Artist, or the Windows author (XPAuthor) when that
	// is all there is; Owner the camera owner's name.
	Artist    string `json:"artist,omitempty"`
	Owner     string `json:"owner,omitempty"`
	Copyright string `json:"copyright,omitempty"`
	// Serial is the camera body's serial number.
	Serial string `json:"serial,omitempty"`
	// Taken is when the picture was taken (DateTimeOriginal, else DateTime),
	// as written ("2019:05:06 07:08:09").
	Taken string `json:"taken,omitempty"`
	// Lat and Lon are the GPS position in decimal degrees, when HasGPS.
	Lat    float64 `json:"lat,omitempty"`
	Lon    float64 `json:"lon,omitempty"`
	HasGPS bool    `json:"has_gps,omitempty"`
	// Uncertainty is the receiver's horizontal positioning error in meters
	// (GPSHPositioningError), when it wrote one.
	Uncertainty float64 `json:"uncertainty,omitempty"`
}

// Empty reports whether the block said nothing useful.
func (x EXIF) Empty() bool {
	return x.Make == "" && x.Model == "" && x.Software == "" && x.Artist == "" && x.Owner == "" &&
		x.Copyright == "" && x.Serial == "" && x.Taken == "" && !x.HasGPS
}

// errNoEXIF is returned for an image without a readable EXIF block.
var errNoEXIF = errors.New("docmeta: no EXIF block")

// The TIFF/EXIF tags read (EXIF 2.32, CIPA DC-008).
const (
	tagMake             = 0x010F
	tagModel            = 0x0110
	tagSoftware         = 0x0131
	tagDateTime         = 0x0132
	tagArtist           = 0x013B
	tagCopyright        = 0x8298
	tagExifIFD          = 0x8769
	tagGPSIFD           = 0x8825
	tagXPAuthor         = 0x9C9D
	tagDateTimeOriginal = 0x9003
	tagCameraOwnerName  = 0xA430
	tagBodySerialNumber = 0xA431
	tagGPSLatitudeRef   = 0x0001
	tagGPSLatitude      = 0x0002
	tagGPSLongitudeRef  = 0x0003
	tagGPSLongitude     = 0x0004
	tagGPSHPosError     = 0x001F
)

// maxIFDEntries bounds the entries read from one IFD.
const maxIFDEntries = 512

// ReadEXIF reads the EXIF block of a JPEG or TIFF image.
func ReadEXIF(img []byte) (EXIF, error) {
	tiff, err := exifTIFF(img)
	if err != nil {
		return EXIF{}, err
	}
	x, err := parseTIFF(tiff)
	if err != nil {
		return EXIF{}, err
	}
	for _, f := range []*string{&x.Make, &x.Model, &x.Software, &x.Artist, &x.Owner, &x.Copyright, &x.Serial,
		&x.Taken} {
		*f = clean(*f)
	}
	if x.Empty() {
		return x, errNoEXIF
	}
	return x, nil
}

// exifTIFF returns the TIFF structure holding the EXIF data: a TIFF file
// itself, or a JPEG's APP1 "Exif" segment.
func exifTIFF(img []byte) ([]byte, error) {
	if bytes.HasPrefix(img, []byte("II*\x00")) || bytes.HasPrefix(img, []byte("MM\x00*")) {
		return img, nil
	}
	if len(img) < 4 || img[0] != 0xFF || img[1] != 0xD8 {
		return nil, errNoEXIF
	}

	for i := 2; i+4 <= len(img); {
		if img[i] != 0xFF {
			return nil, errNoEXIF
		}
		marker := img[i+1]
		// start of scan or end of image: no more metadata segments
		if marker == 0xDA || marker == 0xD9 {
			break
		}
		// markers without a length
		if marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7) || marker == 0xFF {
			i += 2
			continue
		}
		size := int(binary.BigEndian.Uint16(img[i+2 : i+4]))
		if size < 2 || i+2+size > len(img) {
			return nil, errNoEXIF
		}
		seg := img[i+4 : i+2+size]
		if marker == 0xE1 && bytes.HasPrefix(seg, []byte("Exif\x00\x00")) {
			return seg[6:], nil
		}
		i += 2 + size
	}
	return nil, errNoEXIF
}

type tiffReader struct {
	b     []byte
	order binary.ByteOrder
	seen  map[uint32]bool
}

func parseTIFF(b []byte) (EXIF, error) {
	var x EXIF
	if len(b) < 8 {
		return x, errNoEXIF
	}

	r := &tiffReader{b: b, seen: map[uint32]bool{}}
	switch string(b[:2]) {
	case "II":
		r.order = binary.LittleEndian
	case "MM":
		r.order = binary.BigEndian
	default:
		return x, errNoEXIF
	}
	if r.order.Uint16(b[2:4]) != 42 {
		return x, errNoEXIF
	}

	ifd0 := r.ifd(r.order.Uint32(b[4:8]))
	x.Make = r.ascii(ifd0[tagMake])
	x.Model = r.ascii(ifd0[tagModel])
	x.Software = r.ascii(ifd0[tagSoftware])
	x.Artist = r.ascii(ifd0[tagArtist])
	x.Copyright = r.ascii(ifd0[tagCopyright])
	x.Taken = r.ascii(ifd0[tagDateTime])
	if x.Artist == "" {
		x.Artist = r.ucs2(ifd0[tagXPAuthor])
	}

	if e, ok := ifd0[tagExifIFD]; ok {
		exif := r.ifd(r.long(e))
		if t := r.ascii(exif[tagDateTimeOriginal]); t != "" {
			x.Taken = t
		}
		x.Owner = r.ascii(exif[tagCameraOwnerName])
		x.Serial = r.ascii(exif[tagBodySerialNumber])
	}

	if g, ok := ifd0[tagGPSIFD]; ok {
		gps := r.ifd(r.long(g))
		lat, okLat := r.degrees(gps[tagGPSLatitude])
		lon, okLon := r.degrees(gps[tagGPSLongitude])
		if okLat && okLon {
			if strings.HasPrefix(strings.ToUpper(r.ascii(gps[tagGPSLatitudeRef])), "S") {
				lat = -lat
			}
			if strings.HasPrefix(strings.ToUpper(r.ascii(gps[tagGPSLongitudeRef])), "W") {
				lon = -lon
			}
			// 0,0 is what an unset receiver writes, not a place
			if math.Abs(lat) <= 90 && math.Abs(lon) <= 180 && (lat != 0 || lon != 0) {
				x.Lat, x.Lon, x.HasGPS = lat, lon, true
				if u, ok := r.rational(gps[tagGPSHPosError]); ok && u > 0 {
					x.Uncertainty = u
				}
			}
		}
	}
	return x, nil
}

// entry is one IFD entry.
type entry struct {
	typ   uint16
	count uint32
	value []byte // the 4-byte value/offset field
}

// ifd reads the IFD at off, once (a loop of IFD pointers is not followed).
func (r *tiffReader) ifd(off uint32) map[uint16]entry {
	out := map[uint16]entry{}
	if r.seen[off] || int(off)+2 > len(r.b) {
		return out
	}
	r.seen[off] = true

	n := int(r.order.Uint16(r.b[off : off+2]))
	if n > maxIFDEntries {
		n = maxIFDEntries
	}
	for i := 0; i < n; i++ {
		p := int(off) + 2 + 12*i
		if p+12 > len(r.b) {
			break
		}
		out[r.order.Uint16(r.b[p:p+2])] = entry{
			typ:   r.order.Uint16(r.b[p+2 : p+4]),
			count: r.order.Uint32(r.b[p+4 : p+8]),
			value: r.b[p+8 : p+12],
		}
	}
	return out
}

// typeSize is the byte size of one value of a TIFF type.
func typeSize(t uint16) int {
	switch t {
	case 1, 2, 6, 7:
		return 1
	case 3, 8:
		return 2
	case 4, 9, 11:
		return 4
	case 5, 10, 12:
		return 8
	}
	return 0
}

// data returns an entry's value bytes: inline when they fit in four bytes,
// otherwise at the offset the field holds.
func (r *tiffReader) data(e entry) []byte {
	size := typeSize(e.typ) * int(e.count)
	if size <= 0 || size > 1<<20 {
		return nil
	}
	if size <= 4 {
		return e.value[:size]
	}
	off := int(r.order.Uint32(e.value))
	if off < 0 || off+size > len(r.b) {
		return nil
	}
	return r.b[off : off+size]
}

func (r *tiffReader) ascii(e entry) string {
	if e.typ != 2 && e.typ != 7 && e.typ != 1 {
		return ""
	}
	b := r.data(e)
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return strings.TrimSpace(string(b))
}

// ucs2 reads a Windows XP* tag: UTF-16LE text in BYTE values.
func (r *tiffReader) ucs2(e entry) string {
	b := r.data(e)
	if len(b) < 2 {
		return ""
	}
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		v := binary.LittleEndian.Uint16(b[i:])
		if v == 0 {
			break
		}
		u = append(u, v)
	}
	return strings.TrimSpace(string(utf16.Decode(u)))
}

func (r *tiffReader) long(e entry) uint32 {
	switch e.typ {
	case 3:
		return uint32(r.order.Uint16(e.value))
	case 4, 9, 13:
		return r.order.Uint32(e.value)
	}
	return 0
}

// rational reads a single unsigned rational value.
func (r *tiffReader) rational(e entry) (float64, bool) {
	if e.typ != 5 || e.count != 1 {
		return 0, false
	}
	b := r.data(e)
	if len(b) != 8 {
		return 0, false
	}
	num, den := r.order.Uint32(b), r.order.Uint32(b[4:])
	if den == 0 {
		return 0, false
	}
	return float64(num) / float64(den), true
}

// degrees reads a GPS coordinate: three rationals, degrees, minutes and
// seconds.
func (r *tiffReader) degrees(e entry) (float64, bool) {
	if e.typ != 5 || e.count != 3 {
		return 0, false
	}
	b := r.data(e)
	if len(b) != 24 {
		return 0, false
	}
	var v [3]float64
	for i := range v {
		num, den := r.order.Uint32(b[8*i:]), r.order.Uint32(b[8*i+4:])
		if den == 0 {
			return 0, false
		}
		v[i] = float64(num) / float64(den)
	}
	return v[0] + v[1]/60 + v[2]/3600, true
}
