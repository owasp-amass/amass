// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
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

	"github.com/PuerkitoBio/goquery"
	"github.com/caffix/stringset"
	"github.com/geziyor/geziyor"
	"github.com/geziyor/geziyor/client"
	amassnet "github.com/owasp-amass/amass/v4/net"
	"github.com/owasp-amass/amass/v4/net/dns"
	bf "github.com/tylertreat/BoomFilters"
)

const (
	// Accept is the default HTTP Accept header value used by Amass.
	Accept = "text/html,application/json,application/xhtml+xml,application/xml;q=0.5,*/*;q=0.2"
	// AcceptLang is the default HTTP Accept-Language header value used by Amass.
	AcceptLang       = "en-US,en;q=0.5"
	defaultUserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"
	windowsUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"
	darwinUserAgent  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"
	httpTimeout      = 10 * time.Second
	handshakeTimeout = 5 * time.Second
)

var (
	// UserAgent is the default user agent used by Amass during HTTP requests.
	UserAgent   string
	subRE       = dns.AnySubdomainRegex()
	nameStripRE = regexp.MustCompile(`^(u[0-9a-f]{4}|20|22|25|27|2b|2f|3d|3a|40)`)
)

// DefaultClient is the same HTTP client used by the package methods.
var DefaultClient *http.Client

// Header represents the HTTP headers for requests and responses.
type Header map[string]string

// Request represents the HTTP request in the Amass preferred format.
type Request struct {
	URL    string
	Method string
	Header Header
	Body   string
	Auth   *BasicAuth
}

// Response represents the HTTP response in the Amass preferred format.
type Response struct {
	Status     string
	StatusCode int
	Proto      string
	ProtoMajor int
	ProtoMinor int
	Header     Header
	Body       string
	Length     int64
	TLS        *tls.ConnectionState
}

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
			IdleConnTimeout:       10 * time.Second,
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

// HdrToAmassHeader converts a net/http Header to an Amass Header.
func HdrToAmassHeader(hdr http.Header) Header {
	h := make(Header)
	for k, v := range hdr {
		if len(v) > 0 {
			h[k] = strings.Join(v, ", ")
		}
	}
	return h
}

// ReqToAmassRequest converts a net/http Request to an Amass Request.
func ReqToAmassRequest(req *http.Request) *Request {
	var body string
	if req.Body != nil {
		if b, err := io.ReadAll(req.Body); err == nil {
			body = string(b)
		}
		_ = req.Body.Close()
	}

	var ba *BasicAuth
	if user, pass, ok := req.BasicAuth(); ok {
		ba = &BasicAuth{
			Username: user,
			Password: pass,
		}
	}

	return &Request{
		URL:    req.URL.String(),
		Method: req.Method,
		Header: HdrToAmassHeader(req.Header),
		Body:   body,
		Auth:   ba,
	}
}

// RespToAmassResponse converts a net/http Response to an Amass Response.
func RespToAmassResponse(resp *http.Response) *Response {
	var body string
	if resp.Body != nil {
		if b, err := io.ReadAll(resp.Body); err == nil {
			body = string(b)
		}
		_ = resp.Body.Close()
	}

	return &Response{
		Status:     resp.Status,
		StatusCode: resp.StatusCode,
		Proto:      resp.Proto,
		ProtoMajor: resp.ProtoMajor,
		ProtoMinor: resp.ProtoMinor,
		Header:     HdrToAmassHeader(resp.Header),
		Body:       body,
		Length:     resp.ContentLength,
		TLS:        resp.TLS,
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

// RequestWebPage returns the response headers, body, and status code for the provided URL when successful.
func RequestWebPage(ctx context.Context, r *Request) (*Response, error) {
	if r == nil {
		return nil, errors.New("failed to provide a valid Amass HTTP request")
	}

	if r.Method == "" {
		r.Method = "GET"
	} else if r.Method != "GET" && r.Method != "POST" {
		return nil, errors.New("failed to provide a valid HTTP method")
	}

	req, err := http.NewRequestWithContext(ctx, r.Method, r.URL, strings.NewReader(r.Body))
	if err != nil {
		return nil, err
	}
	req.Close = true

	if r.Auth != nil && r.Auth.Username != "" && r.Auth.Password != "" {
		req.SetBasicAuth(r.Auth.Username, r.Auth.Password)
	}

	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", Accept)
	req.Header.Set("Accept-Language", AcceptLang)
	for k, v := range r.Header {
		req.Header.Set(k, v)
	}

	resp, err := DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	return RespToAmassResponse(resp), nil
}

// Crawl will spider the web page at the URL argument looking while staying within the scope provided.
func Crawl(ctx context.Context, u string, scope []string, max int, callback func(*Request, *Response)) error {
	select {
	case <-ctx.Done():
		return fmt.Errorf("the context expired")
	default:
	}

	var count int
	var m sync.Mutex
	filter := bf.NewDefaultStableBloomFilter(10000, 0.01)
	defer filter.Reset()
	attrs := []string{"action", "cite", "data", "formaction",
		"href", "longdesc", "poster", "src", "srcset", "xmlns"}
	tags := []string{"a", "area", "audio", "base", "blockquote", "button",
		"embed", "form", "frame", "frameset", "html", "iframe", "img", "input",
		"ins", "link", "noframes", "object", "q", "script", "source", "track", "video"}

	g := geziyor.NewGeziyor(&geziyor.Options{
		StartURLs:             []string{u},
		RobotsTxtDisabled:     true,
		UserAgent:             UserAgent,
		LogDisabled:           true,
		ConcurrentRequests:    5,
		RequestDelay:          50 * time.Millisecond,
		RequestDelayRandomize: true,
		ParseFunc: func(g *geziyor.Geziyor, r *client.Response) {
			select {
			case <-ctx.Done():
				return
			default:
			}

			process := func(n string) {
				u, err := r.Request.URL.Parse(n)
				if err != nil {
					return
				}
				if host := u.Hostname(); host == "" || whichDomain(host, scope) == "" {
					return
				}

				m.Lock()
				if s := u.String(); s != "" && !filter.Test([]byte(s)) {
					count++
					// Be sure the crawl has not exceeded the maximum links to be followed
					if max <= 0 || count < max {
						filter.Add([]byte(s))
						g.Get(s, g.Opt.ParseFunc)
					}
				}
				m.Unlock()
			}
			tag := func(i int, s *goquery.Selection) {
				for _, attr := range attrs {
					if name, ok := s.Attr(attr); ok {
						process(name)
					}
				}
			}
			for _, t := range tags {
				r.HTMLDoc.Find(t).Each(tag)
			}

			callback(ReqToAmassRequest(r.Request.Request), &Response{
				Status:     r.Status,
				StatusCode: r.StatusCode,
				Proto:      r.Proto,
				ProtoMajor: r.ProtoMajor,
				ProtoMinor: r.ProtoMinor,
				Header:     HdrToAmassHeader(r.Header),
				Body:       string(r.Body),
				Length:     r.ContentLength,
				TLS:        r.TLS,
			})
		},
	})
	g.Client = client.NewClient(&client.Options{
		MaxBodySize:    50 * 1024 * 1024, // 50MB
		RetryTimes:     2,
		RetryHTTPCodes: []int{408, 500, 502, 503, 504, 522, 524},
	})
	g.Client.Client = DefaultClient

	g.Start()
	return nil
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
	// check hosts for certificates that contain subdomain names
	for _, port := range ports {
		if c, err := TLSConn(ctx, addr, port); err == nil {
			// get the correct certificate in the chain
			certChain := c.ConnectionState().PeerCertificates
			// create the new requests from names found within the cert
			names = append(names, NamesFromCert(certChain[0])...)
			c.Close()
		}

		select {
		case <-ctx.Done():
			return names
		default:
		}
	}
	return names
}

// TLSConn attempts to make a TLS connection with the host on the given port.
func TLSConn(ctx context.Context, host string, port int) (*tls.Conn, error) {
	// set the maximum time allowed for making the connection
	tCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	// obtain the connection
	conn, err := amassnet.DialContext(tCtx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}

	c := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	// attempt to acquire the certificate chain
	if err := c.HandshakeContext(tCtx); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// NamesFromCert parses DNS names out of a TLS certificate.
func NamesFromCert(cert *x509.Certificate) []string {
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
