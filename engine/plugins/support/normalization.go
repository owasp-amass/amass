// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"hash/maphash"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/PuerkitoBio/purell"
	fnparser "github.com/caffix/fullname_parser"
	"github.com/nyaruka/phonenumbers"
	"github.com/owasp-amass/amass/v4/utils/net/http"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	"github.com/owasp-amass/open-asset-model/contact"
	"github.com/owasp-amass/open-asset-model/people"
	"github.com/owasp-amass/open-asset-model/service"
	oamurl "github.com/owasp-amass/open-asset-model/url"
)

var postalHost, postalPort string

func EmailToOAMEmailAddress(e string) *contact.EmailAddress {
	if e == "" {
		return nil
	}
	email := strings.ToLower(strings.TrimSpace(e))

	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return nil
	}
	return &contact.EmailAddress{
		Address:  email,
		Username: parts[0],
		Domain:   parts[1],
	}
}

func FullNameToPerson(raw string) *people.Person {
	if raw == "" {
		return nil
	}

	name := fnparser.ParseFullname(raw)
	if name.First == "" || name.Last == "" {
		return nil
	}

	var fullname string
	if name.Title != "" {
		fullname += name.Title + " "
	}
	fullname += name.First + " "

	if name.Middle != "" {
		fullname += name.Middle + " "
	}
	fullname += name.Last

	if name.Suffix != "" {
		fullname += ", " + name.Suffix
	}

	return &people.Person{
		FullName:   fullname,
		FirstName:  name.First,
		MiddleName: name.Middle,
		FamilyName: name.Last,
	}
}

func PhoneToOAMPhone(phone, ext, country string) *contact.Phone {
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

	return &contact.Phone{
		Raw:           raw,
		E164:          e164,
		CountryAbbrev: strings.ToUpper(country),
		CountryCode:   int(num.GetCountryCode()),
		Ext:           ext,
	}
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

func ServiceWithIdentifier(h *maphash.Hash, sessionid, address string) *service.Service {
	_, _ = h.WriteString(sessionid + address)
	serv := &service.Service{
		Identifier: address + strconv.Itoa(int(h.Sum64())),
	}
	h.Reset()
	return serv
}

func X509ToOAMTLSCertificate(cert *x509.Certificate) *oamcert.TLSCertificate {
	if cert == nil {
		return nil
	}

	var common string
	names := ScrapeSubdomainNames(strings.ToLower(strings.TrimSpace(cert.Subject.CommonName)))
	if len(names) == 0 {
		return nil
	}
	common = names[0]

	c := &oamcert.TLSCertificate{
		Version:               strconv.Itoa(cert.Version),
		SerialNumber:          cert.SerialNumber.String(),
		SubjectCommonName:     common,
		IssuerCommonName:      cert.Issuer.CommonName,
		NotBefore:             TimeToJSONString(&cert.NotBefore),
		NotAfter:              TimeToJSONString(&cert.NotAfter),
		SignatureAlgorithm:    cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm:    cert.PublicKeyAlgorithm.String(),
		IsCA:                  cert.IsCA,
		CRLDistributionPoints: cert.CRLDistributionPoints,
		SubjectKeyID:          string(cert.SubjectKeyId),
		AuthorityKeyID:        string(cert.AuthorityKeyId),
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
	return c
}

func StreetAddressToLocation(address string) *contact.Location {
	if address == "" {
		return nil
	}

	var err error
	var loc contact.Location
	loc.Address, err = expandAddress(address)
	if err != nil {
		return nil
	}

	parsed, err := parseAddress(loc.Address)
	if err != nil || len(parsed.Parts) < 4 {
		return nil
	}

	for _, part := range parsed.Parts {
		switch part.Label {
		case "house":
			loc.Building = part.Value
		case "house_number":
			loc.BuildingNumber = part.Value
		case "road":
			loc.StreetName = part.Value
		case "unit":
			loc.Unit = part.Value
		case "po_box":
			loc.POBox = part.Value
		case "city":
			loc.City = part.Value
		case "state":
			loc.Province = part.Value
		case "postcode":
			loc.PostalCode = part.Value
		case "country":
			loc.Country = part.Value
		case "suburb":
			fallthrough
		case "city_district":
			if s := part.Value; s != "" {
				loc.Locality = s
			}
		}
	}
	if (loc.Building == "" && loc.BuildingNumber == "") ||
		loc.StreetName == "" || loc.City == "" || loc.Province == "" {
		return nil
	}
	return &loc
}

type parsed struct {
	Parts []struct {
		Label string `json:"label"`
		Value string `json:"value"`
	} `json:"parts"`
}

func parseAddress(address string) (*parsed, error) {
	if postalHost == "" || postalPort == "" {
		return nil, errors.New("no postal server information provided")
	}

	resp, err := http.RequestWebPage(context.TODO(), &http.Request{
		URL: "http://" + postalHost + ":" + postalPort + "/parse?address=" + url.QueryEscape(address),
	})
	if err != nil {
		return nil, err
	}

	var p parsed
	if err := json.Unmarshal([]byte("{\"parts\":"+resp.Body+"}"), &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func expandAddress(address string) (string, error) {
	if postalHost == "" || postalPort == "" {
		return "", errors.New("no postal server information provided")
	}

	resp, err := http.RequestWebPage(context.TODO(), &http.Request{
		URL: "http://" + postalHost + ":" + postalPort + "/expand?address=" + url.QueryEscape(address),
	})
	if err != nil {
		return "", err
	}

	type expanded struct {
		Forms []string `json:"forms"`
	}

	var ex expanded
	if err := json.Unmarshal([]byte("{\"forms\":"+resp.Body+"}"), &ex); err != nil {
		return "", err
	}

	num := len(ex.Forms)
	if num == 0 {
		return "", errors.New("the libpostal expansion returned zero normalized strings")
	}
	return ex.Forms[num-1], nil
}
