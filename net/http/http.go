// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package http

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/OWASP/Amass/v3/net/dns"
	"github.com/OWASP/Amass/v3/stringset"
	"github.com/caffix/cloudflare-roundtripper/cfrt"
)

const (
	// UserAgent is the default user agent used by Amass during HTTP requests.
	UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.119 Safari/537.36"

	// Accept is the default HTTP Accept header value used by Amass.
	Accept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"

	// AcceptLang is the default HTTP Accept-Language header value used by Amass.
	AcceptLang = "en-US,en;q=0.8"

	defaultTLSConnectTimeout = 3 * time.Second
	defaultHandshakeDeadline = 5 * time.Second
)

var (
	defaultClient *http.Client
)

func init() {
	jar, _ := cookiejar.New(nil)
	defaultClient = &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          200,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   20 * time.Second,
			ExpectContinueTimeout: 20 * time.Second,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		},
		Jar: jar,
	}
	defaultClient.Transport, _ = cfrt.New(defaultClient.Transport)
}

// CopyCookies copies cookies from one domain to another. Some of our data
// sources rely on shared auth tokens and this avoids sending extra requests
// to have the site reissue cookies for the other domains.
func CopyCookies(src string, dest string) {
	srcURL, _ := url.Parse(src)
	destURL, _ := url.Parse(dest)
	defaultClient.Jar.SetCookies(destURL, defaultClient.Jar.Cookies(srcURL))
}

// CheckCookie checks if a cookie exists in the cookie jar for a given host
func CheckCookie(urlString string, cookieName string) bool {
	cookieURL, _ := url.Parse(urlString)
	found := false
	for _, cookie := range defaultClient.Jar.Cookies(cookieURL) {
		if cookie.Name == cookieName {
			found = true
			break
		}
	}
	return found
}

// RequestWebPage returns a string containing the entire response for
// the urlstring parameter when successful.
func RequestWebPage(urlstring string, body io.Reader, hvals map[string]string, uid, secret string) (string, error) {
	method := "GET"
	if body != nil {
		method = "POST"
	}
	req, err := http.NewRequest(method, urlstring, body)
	if err != nil {
		return "", err
	}
	if uid != "" && secret != "" {
		req.SetBasicAuth(uid, secret)
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", Accept)
	req.Header.Set("Accept-Language", AcceptLang)
	if hvals != nil {
		for k, v := range hvals {
			req.Header.Set(k, v)
		}
	}

	resp, err := defaultClient.Do(req)
	if err != nil {
		return "", err
	} else if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", errors.New(resp.Status)
	}

	in, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	return string(in), nil
}

// PullCertificateNames attempts to pull a cert from one or more ports on an IP.
func PullCertificateNames(addr string, ports []int) []string {
	var names []string

	// Check hosts for certificates that contain subdomain names
	for _, port := range ports {
		cfg := &tls.Config{InsecureSkipVerify: true}
		// Set the maximum time allowed for making the connection
		ctx, cancel := context.WithTimeout(context.Background(), defaultTLSConnectTimeout)
		defer cancel()
		// Obtain the connection
		d := net.Dialer{}
		conn, err := d.DialContext(ctx, "tcp", addr+":"+strconv.Itoa(port))
		if err != nil {
			continue
		}
		defer conn.Close()

		c := tls.Client(conn, cfg)
		// Attempt to acquire the certificate chain
		errChan := make(chan error, 2)
		// This goroutine will break us out of the handshake
		time.AfterFunc(defaultHandshakeDeadline, func() {
			errChan <- errors.New("Handshake timeout")
		})
		// Be sure we do not wait too long in this attempt
		c.SetDeadline(time.Now().Add(defaultHandshakeDeadline))
		// The handshake is performed in the goroutine
		go func() {
			errChan <- c.Handshake()
		}()
		// The error channel returns handshake or timeout error
		if err = <-errChan; err != nil {
			continue
		}
		// Get the correct certificate in the chain
		certChain := c.ConnectionState().PeerCertificates
		cert := certChain[0]
		// Create the new requests from names found within the cert
		names = append(names, namesFromCert(cert)...)
	}
	return names
}

func namesFromCert(cert *x509.Certificate) []string {
	var cn string

	for _, name := range cert.Subject.Names {
		oid := name.Type
		if len(oid) == 4 && oid[0] == 2 && oid[1] == 5 && oid[2] == 4 {
			if oid[3] == 3 {
				cn = fmt.Sprintf("%s", name.Value)
				break
			}
		}
	}

	subdomains := stringset.New()
	// Add the subject common name to the list of subdomain names
	commonName := dns.RemoveAsteriskLabel(cn)
	if commonName != "" {
		subdomains.Insert(commonName)
	}
	// Add the cert DNS names to the list of subdomain names
	for _, name := range cert.DNSNames {
		n := dns.RemoveAsteriskLabel(name)
		if n != "" {
			subdomains.Insert(n)
		}
	}
	return subdomains.Slice()
}

// ClientCountryCode returns the country code for the public-facing IP address for the host of the process.
func ClientCountryCode() string {
	headers := map[string]string{"Content-Type": "application/json"}

	page, err := RequestWebPage("https://ipapi.co/json", nil, headers, "", "")
	if err != nil {
		return ""
	}

	// Extract the country code from the REST API results
	var ipinfo struct {
		CountryCode string `json:"country"`
	}

	json.Unmarshal([]byte(page), &ipinfo)
	return strings.ToLower(ipinfo.CountryCode)
}
