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
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	amassnet "github.com/OWASP/Amass/v3/net"
	"github.com/OWASP/Amass/v3/net/dns"
	"github.com/OWASP/Amass/v3/stringfilter"
	"github.com/PuerkitoBio/goquery"
	"github.com/caffix/stringset"
	"github.com/geziyor/geziyor"
	"github.com/geziyor/geziyor/client"
)

const (
	// UserAgent is the default user agent used by Amass during HTTP requests.
	UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.49 Safari/537.36"

	// Accept is the default HTTP Accept header value used by Amass.
	Accept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"

	// AcceptLang is the default HTTP Accept-Language header value used by Amass.
	AcceptLang = "en-US,en;q=0.8"

	defaultTLSConnectTimeout = 3 * time.Second
	defaultHandshakeDeadline = 5 * time.Second
)

var (
	subRE          = dns.AnySubdomainRegex()
	crawlRE        = regexp.MustCompile(`\.\w{3,4}($|\?)`)
	crawlFileTypes = []string{".html", ".htm", "xhtml", ".js", ".php"}
	nameStripRE    = regexp.MustCompile(`^u[0-9a-f]{4}|20|22|25|2b|2f|3d|3a|40`)
)

// DefaultClient is the same HTTP client used by the package methods.
var DefaultClient *http.Client

// BasicAuth contains the data used for HTTP basic authentication.
type BasicAuth struct {
	Username string
	Password string
}

func init() {
	jar, _ := cookiejar.New(nil)
	DefaultClient = &http.Client{
		Timeout: 3 * time.Minute,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           amassnet.DialContext,
			MaxIdleConns:          200,
			MaxConnsPerHost:       50,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 10 * time.Second,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		},
		Jar: jar,
	}
}

// CopyCookies copies cookies from one domain to another. Some of our data
// sources rely on shared auth tokens and this avoids sending extra requests
// to have the site reissue cookies for the other domains.
func CopyCookies(src string, dest string) {
	srcURL, _ := url.Parse(src)
	destURL, _ := url.Parse(dest)
	DefaultClient.Jar.SetCookies(destURL, DefaultClient.Jar.Cookies(srcURL))
}

// CheckCookie checks if a cookie exists in the cookie jar for a given host
func CheckCookie(urlString string, cookieName string) bool {
	cookieURL, _ := url.Parse(urlString)
	found := false
	for _, cookie := range DefaultClient.Jar.Cookies(cookieURL) {
		if cookie.Name == cookieName {
			found = true
			break
		}
	}
	return found
}

// RequestWebPage returns a string containing the entire response for the provided URL when successful.
func RequestWebPage(ctx context.Context, u string, body io.Reader, hvals map[string]string, auth *BasicAuth) (string, error) {
	method := "GET"
	if body != nil {
		method = "POST"
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return "", err
	}
	if auth != nil && auth.Username != "" && auth.Password != "" {
		req.SetBasicAuth(auth.Username, auth.Password)
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", Accept)
	req.Header.Set("Accept-Language", AcceptLang)

	for k, v := range hvals {
		req.Header.Set(k, v)
	}

	resp, err := DefaultClient.Do(req)
	if err != nil {
		return "", err
	}

	in, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		err = errors.New(resp.Status)
	}
	return string(in), err
}

// Crawl will spider the web page at the URL argument looking for DNS names within the scope argument.
func Crawl(ctx context.Context, u string, scope []string, max int, filter stringfilter.Filter) ([]string, error) {
	newScope := append([]string{}, scope...)

	target := subRE.FindString(u)
	if target != "" {
		var found bool
		for _, domain := range newScope {
			if target == domain {
				found = true
				break
			}
		}
		if !found {
			newScope = append(newScope, target)
		}
	}

	if filter == nil {
		filter = stringfilter.NewStringFilter()
	}

	var count int
	var m sync.Mutex
	results := stringset.New()
	g := geziyor.NewGeziyor(&geziyor.Options{
		AllowedDomains:        newScope,
		StartURLs:             []string{u},
		Timeout:               5 * time.Minute,
		RobotsTxtDisabled:     true,
		UserAgent:             UserAgent,
		LogDisabled:           true,
		ConcurrentRequests:    5,
		RequestDelay:          750 * time.Millisecond,
		RequestDelayRandomize: true,
		ParseFunc: func(g *geziyor.Geziyor, r *client.Response) {
			for _, n := range subRE.FindAllString(string(r.Body), -1) {
				if name := CleanName(n); whichDomain(name, scope) != "" {
					m.Lock()
					results.Insert(name)
					m.Unlock()
				}
			}

			processURL := func(u string) {
				if p, err := url.Parse(u); err == nil && whichDomain(p.Hostname(), newScope) != "" {
					// Attempt to save the name in our results
					if name := p.Hostname(); whichDomain(name, scope) != "" {
						m.Lock()
						results.Insert(name)
						m.Unlock()
					}
					// Check that the URL has an appropriate scheme for scraping
					if !p.IsAbs() || (p.Scheme != "http" && p.Scheme != "https") {
						return
					}
					// If the URL path has a file extension, check that it's of interest
					if ext := crawlRE.FindString(p.Path); ext != "" {
						ext = strings.ToLower(ext)

						var found bool
						for _, t := range crawlFileTypes {
							if ext == t {
								found = true
								break
							}
						}
						if !found {
							return
						}
					}
					// Remove fragments and check if we've seen this URL before
					p.Fragment = ""
					p.RawFragment = ""
					if filter.Duplicate(p.String()) {
						return
					}
					// Be sure the crawl has not exceeded the maximum links to be followed
					m.Lock()
					count++
					current := count
					m.Unlock()
					if max <= 0 || current < max {
						g.Get(p.String(), g.Opt.ParseFunc)
					}
				}
			}

			r.HTMLDoc.Find("a").Each(func(i int, s *goquery.Selection) {
				if href, ok := s.Attr("href"); ok {
					processURL(r.JoinURL(href))
				}
			})

			r.HTMLDoc.Find("script").Each(func(i int, s *goquery.Selection) {
				if src, ok := s.Attr("src"); ok {
					processURL(r.JoinURL(src))
				}
			})
		},
	})
	options := &client.Options{
		MaxBodySize:    100 * 1024 * 1024, // 100MB
		RetryTimes:     2,
		RetryHTTPCodes: []int{408, 500, 502, 503, 504, 522, 524},
	}
	g.Client = client.NewClient(options)
	g.Client.Client = http.DefaultClient

	done := make(chan struct{}, 2)
	go func() {
		g.Start()
		done <- struct{}{}
	}()

	var err error
	select {
	case <-ctx.Done():
		err = fmt.Errorf("The context expired during the crawl of %s", u)
	case <-done:
		if len(results.Slice()) == 0 {
			err = fmt.Errorf("No DNS names were discovered during the crawl of %s", u)
		}
	}

	return results.Slice(), err
}

func whichDomain(name string, scope []string) string {
	n := strings.TrimSpace(name)

	for _, d := range scope {
		if strings.HasSuffix(n, d) {
			// fork made me do it :>
			nlen := len(n)
			dlen := len(d)
			// Check for exact match first to guard against out of bound index
			if nlen == dlen || n[nlen-dlen-1] == '.' {
				return d
			}
		}
	}
	return ""
}

// PullCertificateNames attempts to pull a cert from one or more ports on an IP.
func PullCertificateNames(ctx context.Context, addr string, ports []int) []string {
	var names []string

	// Check hosts for certificates that contain subdomain names
	for _, port := range ports {
		// Set the maximum time allowed for making the connection
		tCtx, cancel := context.WithTimeout(ctx, defaultTLSConnectTimeout)
		defer cancel()
		// Obtain the connection
		conn, err := amassnet.DialContext(tCtx, "tcp", net.JoinHostPort(addr, strconv.Itoa(port)))
		if err != nil {
			continue
		}
		defer conn.Close()

		c := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
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
func ClientCountryCode(ctx context.Context) string {
	headers := map[string]string{"Content-Type": "application/json"}

	page, err := RequestWebPage(ctx, "https://ipapi.co/json", nil, headers, nil)
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

// CleanName will clean up the names scraped from the web.
func CleanName(name string) string {
	var err error

	name, err = strconv.Unquote("\"" + strings.TrimSpace(name) + "\"")
	if err == nil {
		name = subRE.FindString(name)
	}

	name = strings.ToLower(name)
	for {
		name = strings.Trim(name, "-.")

		if i := nameStripRE.FindStringIndex(name); i != nil {
			name = name[i[1]:]
		} else {
			break
		}
	}

	return name
}
