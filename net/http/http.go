// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package http

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	amassnet "github.com/OWASP/Amass/v3/net"
	"github.com/OWASP/Amass/v3/net/dns"
	"github.com/PuerkitoBio/goquery"
	"github.com/caffix/stringset"
	"github.com/geziyor/geziyor"
	"github.com/geziyor/geziyor/client"
)

const (
	// Accept is the default HTTP Accept header value used by Amass.
	Accept = "text/html,application/json,application/xhtml+xml,application/xml;q=0.5,*/*;q=0.2"
	// AcceptLang is the default HTTP Accept-Language header value used by Amass.
	AcceptLang       = "en-US,en;q=0.5"
	defaultUserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36"
	windowsUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36"
	darwinUserAgent  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_0_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36"
	httpTimeout      = 60 * time.Second
	handshakeTimeout = 20 * time.Second
)

var (
	// UserAgent is the default user agent used by Amass during HTTP requests.
	UserAgent   string
	subRE       = dns.AnySubdomainRegex()
	nameStripRE = regexp.MustCompile(`^u[0-9a-f]{4}|20|22|25|27|2b|2f|3d|3a|40`)
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
		Timeout: httpTimeout,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           amassnet.DialContext,
			MaxIdleConns:          200,
			MaxConnsPerHost:       50,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   handshakeTimeout,
			ExpectContinueTimeout: 5 * time.Second,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		},
		Jar: jar,
	}

	switch runtime.GOOS {
	case "windows":
		UserAgent = windowsUserAgent
	case "darwin":
		UserAgent = darwinUserAgent
	default:
		UserAgent = defaultUserAgent
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
	req.Close = true

	if auth != nil && auth.Username != "" && auth.Password != "" {
		req.SetBasicAuth(auth.Username, auth.Password)
	}

	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", Accept)
	req.Header.Set("Accept-Language", AcceptLang)
	for k, v := range hvals {
		req.Header.Set(k, v)
	}

	var in string
	resp, err := DefaultClient.Do(req)
	if err == nil {
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode < 200 || resp.StatusCode >= 400 {
			err = fmt.Errorf("%d: %s", resp.StatusCode, resp.Status)
		}
		if b, err := ioutil.ReadAll(resp.Body); err == nil {
			in = string(b)
		}
	}
	return in, err
}

// Crawl will spider the web page at the URL argument looking for DNS names within the scope provided.
func Crawl(ctx context.Context, u string, scope []string, max int, f *stringset.Set) ([]string, error) {
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("the context expired")
	default:
	}

	if f == nil {
		f = stringset.New()
		defer f.Close()
	}

	results := stringset.New()
	defer results.Close()

	g := createCrawler(u, scope, max, results, f)
	g.Client = client.NewClient(&client.Options{
		MaxBodySize:    50 * 1024 * 1024, // 50MB
		RetryTimes:     2,
		RetryHTTPCodes: []int{408, 500, 502, 503, 504, 522, 524},
	})
	g.Client.Client = http.DefaultClient

	done := make(chan struct{}, 2)
	go func() {
		g.Start()
		close(done)
	}()

	var err error
	select {
	case <-ctx.Done():
		err = fmt.Errorf("the context expired during the crawl of %s", u)
	case <-done:
		if len(results.Slice()) == 0 {
			err = fmt.Errorf("no DNS names were discovered during the crawl of %s", u)
		}
	}

	return results.Slice(), err
}

func createCrawler(u string, scope []string, max int, results, filter *stringset.Set) *geziyor.Geziyor {
	var count int
	var m sync.Mutex

	return geziyor.NewGeziyor(&geziyor.Options{
		StartURLs:             []string{u},
		Timeout:               5 * time.Minute,
		RobotsTxtDisabled:     true,
		UserAgent:             UserAgent,
		LogDisabled:           true,
		ConcurrentRequests:    5,
		RequestDelay:          750 * time.Millisecond,
		RequestDelayRandomize: true,
		ParseFunc: func(g *geziyor.Geziyor, r *client.Response) {
			process := func(n string) {
				if u, err := r.Request.URL.Parse(n); err == nil {
					host := u.Hostname()
					if host != "" {
						results.Insert(host)
					}
					if whichDomain(host, scope) == "" {
						return
					}

					if s := u.String(); s != "" && !filter.Has(s) {
						// Be sure the crawl has not exceeded the maximum links to be followed
						m.Lock()
						count++
						if max <= 0 || count < max {
							filter.Insert(s)
							g.Get(s, g.Opt.ParseFunc)
						}
						m.Unlock()
					}
				}
			}
			tag := func(i int, s *goquery.Selection) {
				// TODO: add the 'srcset' attr
				attrs := []string{"action", "cite", "data", "formaction",
					"href", "longdesc", "poster", "src", "srcset", "xmlns"}
				for _, attr := range attrs {
					if name, ok := s.Attr(attr); ok {
						process(name)
					}
				}
			}

			tagname := []string{"a", "area", "audio", "base", "blockquote", "button",
				"embed", "form", "frame", "frameset", "html", "iframe", "img", "input",
				"ins", "link", "noframes", "object", "q", "script", "source", "track", "video"}
			for _, t := range tagname {
				r.HTMLDoc.Find(t).Each(tag)
			}
		},
	})
}

func whichDomain(name string, scope []string) string {
	n := strings.TrimSpace(name)

	for _, d := range scope {
		if strings.HasSuffix(n, d) {
			nlen := len(n)
			dlen := len(d)
			// Check for exact match first to guard against out of bounds index
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
		if c, err := TLSConn(ctx, addr, port); err == nil {
			// Get the correct certificate in the chain
			certChain := c.ConnectionState().PeerCertificates
			// Create the new requests from names found within the cert
			names = append(names, namesFromCert(certChain[0])...)
		}

		select {
		case <-ctx.Done():
			return names
		default:
		}
	}
	return names
}

// TLSConn attempts to make a TLS connection with the host on given port
func TLSConn(ctx context.Context, host string, port int) (*tls.Conn, error) {
	// Set the maximum time allowed for making the connection
	tCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	// Obtain the connection
	conn, err := amassnet.DialContext(tCtx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	c := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	// Attempt to acquire the certificate chain
	errChan := make(chan error, 2)
	go func() {
		errChan <- c.Handshake()
	}()

	t := time.NewTimer(handshakeTimeout)
	select {
	case <-t.C:
		err = errors.New("handshake timeout")
	case e := <-errChan:
		err = e
	}
	t.Stop()

	return c, err
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
	defer subdomains.Close()
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

// CleanName will clean up the names scraped from the web.
func CleanName(name string) string {
	clean, err := strconv.Unquote("\"" + strings.TrimSpace(name) + "\"")
	if err != nil {
		return name
	}

	if re := subRE.FindString(clean); re != "" {
		clean = re
	}

	clean = strings.ToLower(clean)
	for {
		clean = strings.Trim(clean, "-.")

		i := nameStripRE.FindStringIndex(clean)
		if i == nil {
			break
		}
		clean = clean[i[1]:]
	}
	return clean
}
