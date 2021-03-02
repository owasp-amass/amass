// Copyright 2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolvers

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ClientSubnetCheck ensures that the provided resolver does not send the EDNS client subnet information.
// The function returns the DNS reply size limit in number of bytes.
func ClientSubnetCheck(resolver string) error {
	client := dns.Client{
		Net:     "udp",
		UDPSize: dns.DefaultMsgSize,
		Timeout: 2 * time.Second,
	}

	msg := QueryMsg("o-o.myaddr.l.google.com", dns.TypeTXT)
	resp, _, err := client.Exchange(msg, resolver)
	if err != nil {
		return fmt.Errorf("ClientSubnetCheck: Failed to query 'o-o.myaddr.l.google.com' using the resolver at %s: %v", resolver, err)
	}

	ans := ExtractAnswers(resp)
	if len(ans) == 0 {
		return fmt.Errorf("ClientSubnetCheck: No answers returned from 'o-o.myaddr.l.google.com' using the resolver at %s", resolver)
	}

	records := AnswersByType(ans, dns.TypeTXT)
	if len(records) == 0 {
		return fmt.Errorf("ClientSubnetCheck: No TXT records returned from 'o-o.myaddr.l.google.com' using the resolver at %s", resolver)
	}

	var found bool
	for _, rr := range records {
		found = strings.HasPrefix(rr.Data, "edns0-client-subnet")
		if found {
			break
		}
	}
	if found {
		return fmt.Errorf("ClientSubnetCheck: The EDNS client subnet data was sent through using resolver %s", resolver)
	}
	return nil
}
