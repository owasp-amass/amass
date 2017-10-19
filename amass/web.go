// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

func GetWebPage(url string) string {
	resp, err := http.Get(url)
	if err != nil {
		return ""
	}

	in, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	return string(in)
}

func GetJSONPage(url string) string {
	client := &http.Client{}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return ""
	}

	req.Header.Add("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}

	in, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	return string(in)
}

func PostXMLWeb(url, body string) string {
	resp, err := http.Post(url, "text/xml", strings.NewReader(body))
	if err != nil {
		return ""
	}

	in, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	return string(in)
}

func PostFormWeb(u, body string) string {
	resp, err := http.PostForm(u, url.Values{"domain": {body}})
	if err != nil {
		return ""
	}

	in, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	return string(in)
}
