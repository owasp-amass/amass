// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/PuerkitoBio/purell"
	"github.com/nyaruka/phonenumbers"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	oamcon "github.com/owasp-amass/open-asset-model/contact"
	oampeop "github.com/owasp-amass/open-asset-model/people"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
	oamurl "github.com/owasp-amass/open-asset-model/url"
)

func FullNameToPerson(raw string) *oampeop.Person {
	name, ok := semantics.ParsePersonName(raw)
	if !ok {
		return nil
	}

	return &oampeop.Person{
		ID:         name.Full,
		FullName:   name.Full,
		FirstName:  name.First,
		MiddleName: name.Middle,
		FamilyName: name.Last,
	}
}

func PhoneToOAMPhone(phone, ext, country string) *oamcon.Phone {
	if phone == "" {
		return nil
	}

	raw := phone
	if ext != "" {
		raw += " Ext. " + ext
	}

	num, err := phonenumbers.Parse(raw, country)
	if err != nil || !phonenumbers.IsValidNumber(num) {
		return nil
	}
	e164 := phonenumbers.Format(num, phonenumbers.E164)

	raw = e164
	ext = num.GetExtension()
	if ext != "" {
		raw += " Ext. " + ext
	}

	// the country the number belongs to, not the hint it was parsed with
	if region := phonenumbers.GetRegionCodeForNumber(num); len(region) == 2 && region != "ZZ" {
		country = region
	}
	return &oamcon.Phone{
		Raw:           raw,
		E164:          e164,
		CountryAbbrev: strings.ToUpper(country),
		CountryCode:   int(num.GetCountryCode()),
		Ext:           ext,
	}
}

// phoneLineTypes names libphonenumber's number types.
var phoneLineTypes = map[phonenumbers.PhoneNumberType]string{
	phonenumbers.FIXED_LINE: "fixed_line", phonenumbers.MOBILE: "mobile",
	phonenumbers.FIXED_LINE_OR_MOBILE: "fixed_line_or_mobile", phonenumbers.TOLL_FREE: "toll_free",
	phonenumbers.PREMIUM_RATE: "premium_rate", phonenumbers.SHARED_COST: "shared_cost",
	phonenumbers.VOIP: "voip", phonenumbers.PERSONAL_NUMBER: "personal_number", phonenumbers.PAGER: "pager",
	phonenumbers.UAN: "uan", phonenumbers.VOICEMAIL: "voicemail",
}

// PhoneDetails reads an E.164 number offline (libphonenumber): its line
// type (fixed_line, mobile, toll_free, voip, …) and the area it was issued
// in, in English. Either is "" when the numbering plan does not say.
func PhoneDetails(e164 string) (lineType, region string) {
	num, err := phonenumbers.Parse(e164, "")
	if err != nil || !phonenumbers.IsValidNumber(num) {
		return "", ""
	}
	lineType = phoneLineTypes[phonenumbers.GetNumberType(num)]
	region, _ = phonenumbers.GetGeocodingForNumber(num, "en")
	return lineType, strings.TrimSpace(region)
}

func RawURLToOAM(raw string) *oamurl.URL {
	if raw == "" {
		return nil
	}

	flags := purell.FlagLowercaseScheme | purell.FlagLowercaseHost | purell.FlagUppercaseEscapes
	flags |= purell.FlagDecodeDWORDHost | purell.FlagDecodeHexHost | purell.FlagDecodeOctalHost
	flags |= purell.FlagRemoveDuplicateSlashes | purell.FlagRemoveEmptyPortSeparator | purell.FlagRemoveUnnecessaryHostDots
	normalized, err := purell.NormalizeURLString(raw, flags)
	if err != nil {
		return nil
	}

	if u, err := url.Parse(normalized); err == nil && u != nil {
		ou := &oamurl.URL{
			Raw:      u.String(),
			Scheme:   u.Scheme,
			Username: u.User.Username(),
			Host:     u.Hostname(),
			Path:     u.Path,
			Fragment: u.Fragment,
		}
		if port := u.Port(); port != "" {
			if i, err := strconv.Atoi(port); err == nil {
				ou.Port = i
			}
		} else {
			ou.Port = schemeToPort(u.Scheme)
		}
		if pass, ok := u.User.Password(); ok && pass != "" {
			ou.Password = pass
		}
		return ou
	}
	return nil
}

func schemeToPort(scheme string) int {
	var port int

	switch scheme {
	case "ftp-data":
		port = 20
	case "ftp":
		port = 21
	case "ssh":
		port = 22
	case "telnet":
		port = 23
	case "smtp":
		port = 25
	case "domain":
		port = 53
	case "tftp":
		port = 69
	case "http":
		port = 80
	case "sftp":
		port = 115
	case "ntp":
		port = 123
	case "imap":
		port = 143
	case "snmp":
		port = 161
	case "print-srv":
		port = 170
	case "bgp":
		port = 179
	case "irc":
		port = 194
	case "imap3":
		port = 220
	case "ldap":
		port = 389
	case "https":
		port = 443
	case "syslog":
		port = 514
	case "printer":
		port = 515
	case "ipp":
		port = 631
	case "ldaps":
		port = 636
	case "rsync":
		port = 873
	case "ftps-data":
		port = 989
	case "ftps":
		port = 990
	case "telnets":
		port = 992
	case "imaps":
		port = 993
	case "pop3s":
		port = 995
	}

	return port
}

func TimeToJSONString(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format("2006-01-02T15:04:05Z07:00")
}

func ServiceWithIdentifier(address, protocol string, port int) *oamplat.Service {
	name := fmt.Sprintf("%s:%s:%d", address, strings.ToLower(protocol), port)

	return &oamplat.Service{ID: name + "-" + Hash64Hex(name)}
}

func Hash64Hex(s string) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	var b [8]byte
	sum := h.Sum(nil) // 8 bytes
	copy(b[:], sum)
	return hex.EncodeToString(b[:]) // 16 hex chars
}

// KeyIDString formats a certificate key identifier as colon-separated
// uppercase hex, as OpenSSL prints it. Storing the raw bytes is lossy: JSON
// replaces bytes that are not valid UTF-8.
func KeyIDString(id []byte) string {
	if len(id) == 0 {
		return ""
	}

	parts := make([]string, len(id))
	for i, b := range id {
		parts[i] = fmt.Sprintf("%02X", b)
	}

	return strings.Join(parts, ":")
}

// publicKeySHA256 is the lower-case hex SHA-256 of a certificate's DER
// SubjectPublicKeyInfo: a stable identifier for the public key itself, so two
// certificates built from the same key pair share it.
func publicKeySHA256(cert *x509.Certificate) string {
	if len(cert.RawSubjectPublicKeyInfo) == 0 {
		return ""
	}

	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// OIDBIMIKeyUsage is the extended key usage of a mark certificate for Brand
// Indicators for Message Identification (the BIMI Group's Verified Mark
// Certificate Requirements, section 7.1.2.3).
var OIDBIMIKeyUsage = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 31}

// X509ContactKey is the key of the ContactRecord holding a certificate's
// subject or issuer (role "Subject" or "Issuer"), so every collector that
// adds to it reaches the same record.
func X509ContactKey(cert *x509.Certificate, role string) string {
	return "x509 Certificate: " + cert.SerialNumber.String() + ", " + role
}

func X509ToOAMTLSCertificate(cert *x509.Certificate) *oamcert.TLSCertificate {
	if cert == nil {
		return nil
	}

	c := &oamcert.TLSCertificate{
		Version:               strconv.Itoa(cert.Version),
		SerialNumber:          cert.SerialNumber.String(),
		SubjectCommonName:     cert.Subject.CommonName,
		IssuerCommonName:      cert.Issuer.CommonName,
		NotBefore:             TimeToJSONString(&cert.NotBefore),
		NotAfter:              TimeToJSONString(&cert.NotAfter),
		SignatureAlgorithm:    cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm:    cert.PublicKeyAlgorithm.String(),
		IsCA:                  cert.IsCA,
		CRLDistributionPoints: cert.CRLDistributionPoints,
		SubjectKeyID:          KeyIDString(cert.SubjectKeyId),
		AuthorityKeyID:        KeyIDString(cert.AuthorityKeyId),
		PublicKeySHA256:       publicKeySHA256(cert),
	}

	if cert.KeyUsage&x509.KeyUsageDigitalSignature > 0 {
		c.KeyUsage = append(c.KeyUsage, oamcert.KeyUsageDigitalSignature)
	}
	if cert.KeyUsage&x509.KeyUsageContentCommitment > 0 {
		c.KeyUsage = append(c.KeyUsage, oamcert.KeyUsageContentCommitment)
	}
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment > 0 {
		c.KeyUsage = append(c.KeyUsage, oamcert.KeyUsageKeyEncipherment)
	}
	if cert.KeyUsage&x509.KeyUsageDataEncipherment > 0 {
		c.KeyUsage = append(c.KeyUsage, oamcert.KeyUsageDataEncipherment)
	}
	if cert.KeyUsage&x509.KeyUsageKeyAgreement > 0 {
		c.KeyUsage = append(c.KeyUsage, oamcert.KeyUsageKeyAgreement)
	}
	if cert.KeyUsage&x509.KeyUsageCertSign > 0 {
		c.KeyUsage = append(c.KeyUsage, oamcert.KeyUsageCertSign)
	}
	if cert.KeyUsage&x509.KeyUsageCRLSign > 0 {
		c.KeyUsage = append(c.KeyUsage, oamcert.KeyUsageCRLSign)
	}
	if cert.KeyUsage&x509.KeyUsageEncipherOnly > 0 {
		c.KeyUsage = append(c.KeyUsage, oamcert.KeyUsageEncipherOnly)
	}
	if cert.KeyUsage&x509.KeyUsageDecipherOnly > 0 {
		c.KeyUsage = append(c.KeyUsage, oamcert.KeyUsageDecipherOnly)
	}

	for _, usage := range cert.ExtKeyUsage {
		switch usage {
		case x509.ExtKeyUsageAny:
			c.ExtKeyUsage = append(c.ExtKeyUsage, oamcert.ExtKeyUsageAny)
		case x509.ExtKeyUsageServerAuth:
			c.ExtKeyUsage = append(c.ExtKeyUsage, oamcert.ExtKeyUsageServerAuth)
		case x509.ExtKeyUsageClientAuth:
			c.ExtKeyUsage = append(c.ExtKeyUsage, oamcert.ExtKeyUsageClientAuth)
		case x509.ExtKeyUsageCodeSigning:
			c.ExtKeyUsage = append(c.ExtKeyUsage, oamcert.ExtKeyUsageCodeSigning)
		case x509.ExtKeyUsageEmailProtection:
			c.ExtKeyUsage = append(c.ExtKeyUsage, oamcert.ExtKeyUsageEmailProtection)
		case x509.ExtKeyUsageIPSECEndSystem:
			c.ExtKeyUsage = append(c.ExtKeyUsage, oamcert.ExtKeyUsageIPSECEndSystem)
		case x509.ExtKeyUsageIPSECTunnel:
			c.ExtKeyUsage = append(c.ExtKeyUsage, oamcert.ExtKeyUsageIPSECTunnel)
		case x509.ExtKeyUsageIPSECUser:
			c.ExtKeyUsage = append(c.ExtKeyUsage, oamcert.ExtKeyUsageIPSECUser)
		case x509.ExtKeyUsageTimeStamping:
			c.ExtKeyUsage = append(c.ExtKeyUsage, oamcert.ExtKeyUsageTimeStamping)
		case x509.ExtKeyUsageOCSPSigning:
			c.ExtKeyUsage = append(c.ExtKeyUsage, oamcert.ExtKeyUsageOCSPSigning)
		case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
			c.ExtKeyUsage = append(c.ExtKeyUsage, oamcert.ExtKeyUsageMicrosoftServerGatedCrypto)
		case x509.ExtKeyUsageNetscapeServerGatedCrypto:
			c.ExtKeyUsage = append(c.ExtKeyUsage, oamcert.ExtKeyUsageNetscapeServerGatedCrypto)
		case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
			c.ExtKeyUsage = append(c.ExtKeyUsage, oamcert.ExtKeyUsageMicrosoftCommercialCodeSigning)
		case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
			c.ExtKeyUsage = append(c.ExtKeyUsage, oamcert.ExtKeyUsageMicrosoftKernelCodeSigning)
		default:
			c.ExtKeyUsage = append(c.ExtKeyUsage, "Unknown")
		}
	}
	for _, oid := range cert.UnknownExtKeyUsage {
		if oid.Equal(OIDBIMIKeyUsage) {
			c.ExtKeyUsage = append(c.ExtKeyUsage, oamcert.ExtKeyUsageBIMI)
		}
	}
	return c
}

// transferDateLayouts are the date forms funding sources give, from the most
// to the least precise.
var transferDateLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05",
	"2006-01-02",
	"01/02/2006",
	"2006-01",
	"2006",
}

// TransferDate returns a funds transfer's exchange date in RFC 3339, the form
// the Asset Database accepts, from the date forms funding sources give: a
// timestamp, a date ("2009-09-18", "09/18/2009", or "2009-09-18+01:00" with a
// zone offset, kept as that calendar day), a month ("2009-09") or a year
// ("2019", for a fiscal or tax year), the last two as their first day.
// A value in no known form is returned as given.
func TransferDate(raw string) string {
	s := strings.TrimSpace(raw)
	for _, layout := range transferDateLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	// A date with a zone offset (TED's "2024-03-01+01:00") names a calendar
	// day, which converting to UTC would move, so the day is kept.
	if t, err := time.Parse("2006-01-02Z07:00", s); err == nil {
		return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	}
	return raw
}
