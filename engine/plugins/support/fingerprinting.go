// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	jarm "github.com/caffix/jarm-go"
	"github.com/owasp-amass/amass/v4/utils/net"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/network"
)

func JARMFingerprint(target oam.Asset, portrel *general.PortRelation) (string, error) {
	var ipv6 bool
	var host string

	if fqdn, ok := target.(*oamdns.FQDN); ok {
		host = fqdn.Name
	} else if ip, ok := target.(*network.IPAddress); ok {
		ipv6 = ip.Address.Is6()
		host = ip.Address.String()
	} else {
		return "", errors.New("target must be a FQDN or IPAddress")
	}

	addr := host
	if ipv6 {
		addr = "[" + addr + "]"
	}
	addr += ":" + strconv.Itoa(portrel.PortNumber)

	var results []string
	for _, probe := range jarm.GetProbes(host, portrel.PortNumber) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		c, err := net.DialContext(ctx, "tcp", addr)
		if err != nil {
			return "", err
		}
		defer c.Close()

		data := jarm.BuildProbe(probe)
		_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write(data); err != nil {
			results = append(results, "")
			continue
		}

		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 1484)
		n, err := c.Read(buf)
		if err != nil || n == 0 {
			results = append(results, "")
			continue
		}
		data = buf[:n]

		ans, err := jarm.ParseServerHello(data, probe)
		if err != nil {
			results = append(results, "")
			continue
		}
		results = append(results, ans)
	}

	hash := jarm.RawHashToFuzzyHash(strings.Join(results, ","))
	if hash == "00000000000000000000000000000000000000000000000000000000000000" {
		return "", errors.New("probes were not successful against the target")
	}
	return hash, nil
}
