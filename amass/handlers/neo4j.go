// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package handlers

import (
	bolt "github.com/johnnadratowski/golang-neo4j-bolt-driver"
)

// Neo4j is the client object for a Neo4j graph database connection.
type Neo4j struct {
	driver bolt.Driver
	conn   bolt.Conn
}

// NewNeo4j returns a client object that implements the Amass DataHandler interface.
// The url param typically looks like the following: neo4j:DoNotUseThisPassword@localhost:7687
func NewNeo4j(url string) (*Neo4j, error) {
	var err error

	neo4j := &Neo4j{driver: bolt.NewDriver()}

	neo4j.conn, err = neo4j.driver.OpenNeo("bolt://" + url)
	if err != nil {
		return nil, err
	}
	return neo4j, nil
}

// Close cleans up the Neo4j client object.
func (n *Neo4j) Close() {
	n.conn.Close()
}

// String returns a description for the Neo4j client object.
func (n *Neo4j) String() string {
	return "Neo4j Database Handler"
}

// Insert implements the Amass DataHandler interface.
func (n *Neo4j) Insert(data *DataOptsParams) error {
	var err error

	switch data.Type {
	case OptDomain:
		err = n.insertDomain(data)
	case OptCNAME:
		err = n.insertCNAME(data)
	case OptA:
		err = n.insertA(data)
	case OptAAAA:
		err = n.insertAAAA(data)
	case OptPTR:
		err = n.insertPTR(data)
	case OptSRV:
		err = n.insertSRV(data)
	case OptNS:
		err = n.insertNS(data)
	case OptMX:
		err = n.insertMX(data)
	case OptInfrastructure:
		err = n.insertInfrastructure(data)
	}
	return err
}

func (n *Neo4j) insertDomain(data *DataOptsParams) error {
	params := map[string]interface{}{
		"timestamp": data.Timestamp,
		"sdomain":   data.Domain,
		"tag":       data.Tag,
		"source":    data.Source,
	}

	_, err := n.conn.ExecNeo("MERGE (n:Subdomain {name: {sdomain}}) "+
		"ON CREATE SET n.tag = {tag}, n.source = {source} "+
		"SET n:Subdomain:Domain", params)
	return err
}

func (n *Neo4j) insertSubdomain(data *DataOptsParams) error {
	params := map[string]interface{}{
		"timestamp": data.Timestamp,
		"sname":     data.Name,
		"sdomain":   data.Domain,
		"tag":       data.Tag,
		"source":    data.Source,
	}

	_, err := n.conn.ExecNeo("MERGE (n:Subdomain {name: {sname}}) "+
		"ON CREATE SET n.tag = {tag}, n.source = {source}", params)
	if err != nil {
		return err
	}

	_, err = n.conn.ExecNeo("MATCH (domain:Domain {name: {sdomain}}) "+
		"MATCH (target:Subdomain {name: {sname}}) "+
		"MERGE (domain)-[:ROOT_OF]->(target)", params)
	if err != nil {
		return err
	}
	return nil
}

func (n *Neo4j) insertCNAME(data *DataOptsParams) error {
	params := map[string]interface{}{
		"timestamp": data.Timestamp,
		"sname":     data.Name,
		"sdomain":   data.Domain,
		"tname":     data.TargetName,
		"tdomain":   data.TargetDomain,
		"tag":       data.Tag,
		"source":    data.Source,
	}

	if data.Name != data.Domain {
		if err := n.insertSubdomain(data); err != nil {
			return err
		}
	}

	if data.TargetName != data.TargetDomain {
		err := n.insertSubdomain(&DataOptsParams{
			Timestamp: data.Timestamp,
			Name:      data.TargetName,
			Domain:    data.TargetDomain,
			Tag:       data.Tag,
			Source:    data.Source,
		})
		if err != nil {
			return err
		}
	}

	_, err := n.conn.ExecNeo("MATCH (source:Subdomain {name: {sname}}) "+
		"MATCH (target:Subdomain {name: {tname}}) "+
		"MERGE (source)-[:CNAME_TO]->(target)", params)
	return err
}

func (n *Neo4j) insertA(data *DataOptsParams) error {
	params := map[string]interface{}{
		"timestamp": data.Timestamp,
		"name":      data.Name,
		"domain":    data.Domain,
		"addr":      data.Address,
		"type":      "IPv4",
		"tag":       data.Tag,
		"source":    data.Source,
	}

	if data.Name != data.Domain {
		if err := n.insertSubdomain(data); err != nil {
			return err
		}
	}

	_, err := n.conn.ExecNeo("MERGE (:IPAddress {addr: {addr}, type: {type}})", params)
	if err != nil {
		return err
	}

	_, err = n.conn.ExecNeo("MATCH (source:Subdomain {name: {name}}) "+
		"MATCH (address:IPAddress {addr: {addr}, type: {type}}) "+
		"MERGE (source)-[:A_TO]->(address)", params)
	return err
}

func (n *Neo4j) insertAAAA(data *DataOptsParams) error {
	params := map[string]interface{}{
		"timestamp": data.Timestamp,
		"name":      data.Name,
		"domain":    data.Domain,
		"addr":      data.Address,
		"type":      "IPv6",
		"tag":       data.Tag,
		"source":    data.Source,
	}

	if data.Name != data.Domain {
		if err := n.insertSubdomain(data); err != nil {
			return err
		}
	}

	_, err := n.conn.ExecNeo("MERGE (:IPAddress {addr: {addr}, type: {type}})", params)
	if err != nil {
		return err
	}

	_, err = n.conn.ExecNeo("MATCH (source:Subdomain {name: {name}}) "+
		"MATCH (address:IPAddress {addr: {addr}, type: {type}}) "+
		"MERGE (source)-[:AAAA_TO]->(address)", params)
	return err
}

func (n *Neo4j) insertPTR(data *DataOptsParams) error {
	params := map[string]interface{}{
		"timestamp": data.Timestamp,
		"name":      data.Name,
		"domain":    data.Domain,
		"target":    data.TargetName,
		"tag":       data.Tag,
		"source":    data.Source,
	}

	if data.TargetName != data.Domain {
		err := n.insertSubdomain(&DataOptsParams{
			Timestamp: data.Timestamp,
			Name:      data.TargetName,
			Domain:    data.Domain,
			Tag:       data.Tag,
			Source:    data.Source,
		})
		if err != nil {
			return err
		}
	}

	_, err := n.conn.ExecNeo("MERGE (:PTR {name: {name}})", params)
	if err != nil {
		return err
	}

	_, err = n.conn.ExecNeo("MATCH (ptr:PTR {name: {name}}), "+
		"(target:Subdomain {name: {target}}) "+
		"MERGE (ptr)-[:PTR_TO]->(target)", params)
	return err
}

func (n *Neo4j) insertSRV(data *DataOptsParams) error {
	params := map[string]interface{}{
		"timestamp": data.Timestamp,
		"name":      data.Name,
		"domain":    data.Domain,
		"service":   data.Service,
		"target":    data.TargetName,
		"tag":       data.Tag,
		"source":    data.Source,
	}

	if data.Name != data.Domain {
		_, err := n.conn.ExecNeo("MERGE (n:Subdomain {name: {name}}) "+
			"ON CREATE SET n.tag = {tag}, n.source = {source}", params)
		if err != nil {
			return err
		}
	}

	_, err := n.conn.ExecNeo("MERGE (n:Subdomain {name: {service}}) "+
		"ON CREATE SET n.tag = {tag}, n.source = {source}", params)
	if err != nil {
		return err
	}

	_, err = n.conn.ExecNeo("MERGE (n:Subdomain {name: {target}}) "+
		"ON CREATE SET n.tag = {tag}, n.source = {source}", params)
	if err != nil {
		return err
	}

	_, err = n.conn.ExecNeo("MATCH (domain:Domain {name: {domain}}), "+
		"(srv:Subdomain {name: {service}}) "+
		"MERGE (domain)-[:ROOT_OF]->(srv)", params)
	if err != nil {
		return err
	}

	_, err = n.conn.ExecNeo("MATCH (srv:Subdomain {name: {service}}), "+
		"(source:Subdomain {name: {name}}) "+
		"MERGE (srv)-[:SERVICE_FOR]->(source)", params)
	if err != nil {
		return err
	}

	_, err = n.conn.ExecNeo("MATCH (srv:Subdomain {name: {service}}), "+
		"(target:Subdomain {name: {target}}) "+
		"MERGE (srv)-[:SRV_TO]->(target)", params)
	return err
}

func (n *Neo4j) insertNS(data *DataOptsParams) error {
	params := map[string]interface{}{
		"timestamp": data.Timestamp,
		"name":      data.Name,
		"domain":    data.Domain,
		"target":    data.TargetName,
		"tdomain":   data.TargetDomain,
		"tag":       data.Tag,
		"source":    data.Source,
	}

	_, err := n.conn.ExecNeo("MERGE (n:Subdomain {name: {name}}) "+
		"ON CREATE SET n.tag = {tag}, n.source = {source}", params)
	if err != nil {
		return err
	}

	_, err = n.conn.ExecNeo("MERGE (n:Subdomain {name: {target}}) "+
		"ON CREATE SET n.tag = {tag}, n.source = {source} "+
		"SET n:Subdomain:NS", params)
	if err != nil {
		return err
	}

	if data.TargetName != data.TargetDomain {
		_, err = n.conn.ExecNeo("MATCH (domain:Domain {name: {tdomain}}) "+
			"MATCH (nameserver:Subdomain {name: {target}}) "+
			"MERGE (domain)-[:ROOT_OF]->(nameserver)", params)
		if err != nil {
			return err
		}
	}

	_, err = n.conn.ExecNeo("MATCH (source:Subdomain {name: {name}}) "+
		"MATCH (nameserver:Subdomain {name: {target}}) "+
		"MERGE (source)-[:NS_TO]->(nameserver)", params)
	return err
}

func (n *Neo4j) insertMX(data *DataOptsParams) error {
	params := map[string]interface{}{
		"timestamp": data.Timestamp,
		"name":      data.Name,
		"domain":    data.Domain,
		"target":    data.TargetName,
		"tdomain":   data.TargetDomain,
		"tag":       data.Tag,
		"source":    data.Source,
	}

	_, err := n.conn.ExecNeo("MERGE (n:Subdomain {name: {name}}) "+
		"ON CREATE SET n.tag = {tag}, n.source = {source}", params)
	if err != nil {
		return err
	}

	_, err = n.conn.ExecNeo("MERGE (n:Subdomain {name: {target}}) "+
		"ON CREATE SET n.tag = {tag}, n.source = {source} "+
		"SET n:Subdomain:MX", params)
	if err != nil {
		return err
	}

	if data.TargetName != data.TargetDomain {
		_, err = n.conn.ExecNeo("MATCH (domain:Domain {name: {tdomain}}) "+
			"MATCH (mailserver:Subdomain {name: {target}}) "+
			"MERGE (domain)-[:ROOT_OF]->(mailserver)", params)
		if err != nil {
			return err
		}
	}

	_, err = n.conn.ExecNeo("MATCH (source:Subdomain {name: {name}}) "+
		"MATCH (mailserver:Subdomain {name: {target}}) "+
		"MERGE (source)-[:MX_TO]->(mailserver)", params)
	return err
}

func (n *Neo4j) insertInfrastructure(data *DataOptsParams) error {
	params := map[string]interface{}{
		"timestamp": data.Timestamp,
		"addr":      data.Address,
		"asn":       data.ASN,
		"cidr":      data.CIDR,
		"desc":      data.Description,
	}

	_, err := n.conn.ExecNeo("MERGE (:Netblock {cidr: {cidr}})", params)
	if err != nil {
		return err
	}

	_, err = n.conn.ExecNeo("MATCH (address:IPAddress {addr: {addr}}) "+
		"MATCH (netblock:Netblock {cidr: {cidr}}) "+
		"MERGE (netblock)-[:CONTAINS]->(address)", params)
	if err != nil {
		return err
	}

	_, err = n.conn.ExecNeo("MERGE (:AS {asn: {asn}, desc: {desc}})", params)
	if err != nil {
		return err
	}

	_, err = n.conn.ExecNeo("MATCH (as:AS {asn: {asn}}) "+
		"MATCH (netblock:Netblock {cidr: {cidr}}) "+
		"MERGE (as)-[:HAS_PREFIX]->(netblock)", params)
	return err
}
