// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package handlers

import (
	"net"

	bolt "github.com/johnnadratowski/golang-neo4j-bolt-driver"
	//"github.com/johnnadratowski/golang-neo4j-bolt-driver/structures/graph"
)

type Neo4j struct {
	driver bolt.Driver
	conn   bolt.Conn
}

// url param will typically look like the following: neo4j:DoNotUseThisPassword@localhost:7687
func NewNeo4j(url string) (*Neo4j, error) {
	var err error

	neo4j := &Neo4j{driver: bolt.NewDriver()}

	neo4j.conn, err = neo4j.driver.OpenNeo("bolt://" + url)
	if err != nil {
		return nil, err
	}
	return neo4j, nil
}

func (n *Neo4j) Close() {
	n.conn.Close()
}

func (n *Neo4j) InsertDomain(domain, tag, source string) {
	params := map[string]interface{}{
		"name":   domain,
		"tag":    tag,
		"source": source,
	}

	n.conn.ExecNeo("MERGE (n:Subdomain {name: {name}}) "+
		"ON CREATE SET n.tag = {tag}, n.source = {source} "+
		"SET n:Subdomain:Domain", params)
}

func (n *Neo4j) InsertCNAME(name, domain, target, tdomain, tag, source string) {
	params := map[string]interface{}{
		"sname":   name,
		"sdomain": domain,
		"tname":   target,
		"tdomain": tdomain,
		"tag":     tag,
		"source":  source,
	}

	if name != domain {
		n.conn.ExecNeo("MERGE (n:Subdomain {name: {sname}}) "+
			"ON CREATE SET n.tag = {tag}, n.source = {source}", params)

		n.conn.ExecNeo("MATCH (domain:Domain {name: {sdomain}}) "+
			"MATCH (target:Subdomain {name: {sname}}) "+
			"MERGE (domain)-[:ROOT_OF]->(target)", params)
	}

	if target != tdomain {
		n.conn.ExecNeo("MERGE (n:Subdomain {name: {tname}}) "+
			"ON CREATE SET n.tag = {tag}, n.source = {source}", params)

		n.conn.ExecNeo("MATCH (domain:Domain {name: {tdomain}}) "+
			"MATCH (target:Subdomain {name: {tname}}) "+
			"MERGE (domain)-[:ROOT_OF]->(target)", params)
	}

	n.conn.ExecNeo("MATCH (source:Subdomain {name: {sname}}) "+
		"MATCH (target:Subdomain {name: {tname}}) "+
		"MERGE (source)-[:CNAME_TO]->(target)", params)
}

func (n *Neo4j) InsertA(name, domain, addr, tag, source string) {
	params := map[string]interface{}{
		"name":   name,
		"domain": domain,
		"addr":   addr,
		"type":   "IPv4",
		"tag":    tag,
		"source": source,
	}

	if name != domain {
		n.conn.ExecNeo("MERGE (n:Subdomain {name: {name}}) "+
			"ON CREATE SET n.tag = {tag}, n.source = {source}", params)

		n.conn.ExecNeo("MATCH (domain:Domain {name: {domain}}) "+
			"MATCH (target:Subdomain {name: {name}}) "+
			"MERGE (domain)-[:ROOT_OF]->(target)", params)
	}

	n.conn.ExecNeo("MERGE (:IPAddress {addr: {addr}, type: {type}})", params)

	n.conn.ExecNeo("MATCH (source:Subdomain {name: {name}}) "+
		"MATCH (address:IPAddress {addr: {addr}, type: {type}}) "+
		"MERGE (source)-[:A_TO]->(address)", params)
}

func (n *Neo4j) InsertAAAA(name, domain, addr, tag, source string) {
	params := map[string]interface{}{
		"name":   name,
		"domain": domain,
		"addr":   addr,
		"type":   "IPv6",
		"tag":    tag,
		"source": source,
	}

	if name != domain {
		n.conn.ExecNeo("MERGE (n:Subdomain {name: {name}}) "+
			"ON CREATE SET n.tag = {tag}, n.source = {source}", params)

		n.conn.ExecNeo("MATCH (domain:Domain {name: {domain}}) "+
			"MATCH (target:Subdomain {name: {name}}) "+
			"MERGE (domain)-[:ROOT_OF]->(target)", params)
	}

	n.conn.ExecNeo("MERGE (:IPAddress {addr: {addr}, type: {type}})", params)

	n.conn.ExecNeo("MATCH (source:Subdomain {name: {name}}) "+
		"MATCH (address:IPAddress {addr: {addr}, type: {type}}) "+
		"MERGE (source)-[:AAAA_TO]->(address)", params)
}

func (n *Neo4j) InsertPTR(name, domain, target, tag, source string) {
	params := map[string]interface{}{
		"name":   name,
		"domain": domain,
		"target": target,
		"tag":    tag,
		"source": source,
	}

	if target != domain {
		n.conn.ExecNeo("MERGE (n:Subdomain {name: {target}}) "+
			"ON CREATE SET n.tag = {tag}, n.source = {source}", params)

		n.conn.ExecNeo("MATCH (domain:Domain {name: {domain}}), "+
			"(target:Subdomain {name: {target}}) "+
			"MERGE (domain)-[:ROOT_OF]->(target)", params)
	}

	n.conn.ExecNeo("MERGE (:PTR {name: {name}})", params)

	n.conn.ExecNeo("MATCH (ptr:PTR {name: {name}}), "+
		"(target:Subdomain {name: {target}}) "+
		"MERGE (ptr)-[:PTR_TO]->(target)", params)
}

func (n *Neo4j) InsertSRV(name, domain, service, target, tag, source string) {
	params := map[string]interface{}{
		"name":    name,
		"domain":  domain,
		"service": service,
		"target":  target,
		"tag":     tag,
		"source":  source,
	}

	if name != domain {
		n.conn.ExecNeo("MERGE (n:Subdomain {name: {name}}) "+
			"ON CREATE SET n.tag = {tag}, n.source = {source}", params)
	}

	n.conn.ExecNeo("MERGE (n:Subdomain {name: {service}}) "+
		"ON CREATE SET n.tag = {tag}, n.source = {source}", params)

	n.conn.ExecNeo("MERGE (n:Subdomain {name: {target}}) "+
		"ON CREATE SET n.tag = {tag}, n.source = {source}", params)

	n.conn.ExecNeo("MATCH (domain:Domain {name: {domain}}), "+
		"(srv:Subdomain {name: {service}}) "+
		"MERGE (domain)-[:ROOT_OF]->(srv)", params)

	n.conn.ExecNeo("MATCH (srv:Subdomain {name: {service}}), "+
		"(source:Subdomain {name: {name}}) "+
		"MERGE (srv)-[:SERVICE_FOR]->(source)", params)

	n.conn.ExecNeo("MATCH (srv:Subdomain {name: {service}}), "+
		"(target:Subdomain {name: {target}}) "+
		"MERGE (srv)-[:SRV_TO]->(target)", params)
}

func (n *Neo4j) InsertNS(name, domain, target, tdomain, tag, source string) {
	params := map[string]interface{}{
		"name":    name,
		"domain":  domain,
		"target":  target,
		"tdomain": tdomain,
		"tag":     tag,
		"source":  source,
	}

	n.conn.ExecNeo("MERGE (n:Subdomain {name: {name}}) "+
		"ON CREATE SET n.tag = {tag}, n.source = {source}", params)

	n.conn.ExecNeo("MERGE (n:Subdomain {name: {target}}) "+
		"ON CREATE SET n.tag = {tag}, n.source = {source} "+
		"SET n:Subdomain:NS", params)

	if target != tdomain {
		n.conn.ExecNeo("MATCH (domain:Domain {name: {tdomain}}) "+
			"MATCH (nameserver:Subdomain {name: {target}}) "+
			"MERGE (domain)-[:ROOT_OF]->(nameserver)", params)
	}

	n.conn.ExecNeo("MATCH (source:Subdomain {name: {name}}) "+
		"MATCH (nameserver:Subdomain {name: {target}}) "+
		"MERGE (source)-[:NS_TO]->(nameserver)", params)
}

func (n *Neo4j) InsertMX(name, domain, target, tdomain, tag, source string) {
	params := map[string]interface{}{
		"name":    name,
		"domain":  domain,
		"target":  target,
		"tdomain": tdomain,
		"tag":     tag,
		"source":  source,
	}

	n.conn.ExecNeo("MERGE (n:Subdomain {name: {name}}) "+
		"ON CREATE SET n.tag = {tag}, n.source = {source}", params)

	n.conn.ExecNeo("MERGE (n:Subdomain {name: {target}}) "+
		"ON CREATE SET n.tag = {tag}, n.source = {source} "+
		"SET n:Subdomain:MX", params)

	if target != tdomain {
		n.conn.ExecNeo("MATCH (domain:Domain {name: {tdomain}}) "+
			"MATCH (mailserver:Subdomain {name: {target}}) "+
			"MERGE (domain)-[:ROOT_OF]->(mailserver)", params)
	}

	n.conn.ExecNeo("MATCH (source:Subdomain {name: {name}}) "+
		"MATCH (mailserver:Subdomain {name: {target}}) "+
		"MERGE (source)-[:MX_TO]->(mailserver)", params)
}

func (n *Neo4j) InsertInfrastructure(addr string, asn int, cidr *net.IPNet, desc string) {
	params := map[string]interface{}{
		"addr": addr,
		"asn":  asn,
		"cidr": cidr.String(),
		"desc": desc,
	}

	n.conn.ExecNeo("MERGE (:Netblock {cidr: {cidr}})", params)

	n.conn.ExecNeo("MATCH (address:IPAddress {addr: {addr}}) "+
		"MATCH (netblock:Netblock {cidr: {cidr}}) "+
		"MERGE (netblock)-[:CONTAINS]->(address)", params)

	n.conn.ExecNeo("MERGE (:AS {asn: {asn}, desc: {desc}})", params)

	n.conn.ExecNeo("MATCH (as:AS {asn: {asn}}) "+
		"MATCH (netblock:Netblock {cidr: {cidr}}) "+
		"MERGE (as)-[:HAS_PREFIX]->(netblock)", params)
}
