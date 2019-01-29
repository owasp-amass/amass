// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package handlers

import (
	"fmt"
	"log"
	"sync"

	bolt "github.com/johnnadratowski/golang-neo4j-bolt-driver"
)

// Neo4j is the client object for a Neo4j graph database connection.
type Neo4j struct {
	sync.Mutex
	driver bolt.Driver
	conn   bolt.Conn
}

// NewNeo4j returns a client object that implements the Amass DataHandler interface.
// The url param typically looks like the following: localhost:7687
func NewNeo4j(url, username, password string, l *log.Logger) (*Neo4j, error) {
	var err error

	neo4j := &Neo4j{driver: bolt.NewDriver()}

	if username != "" && password != "" {
		url = fmt.Sprintf("%s:%s@%s", username, password, url)
	}
	neo4j.conn, err = neo4j.driver.OpenNeo("bolt://" + url)
	if err != nil {
		if l != nil {
			l.Println("Neo4j: Lost connection to the database: " + err.Error())
		}
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
	n.Lock()
	defer n.Unlock()

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
		"uuid":      data.UUID,
		"timestamp": data.Timestamp,
		"sdomain":   data.Domain,
		"tag":       data.Tag,
		"source":    data.Source,
	}

	_, err := n.conn.ExecNeo("MERGE (n:domain {name: {sdomain}, enum: {uuid}}) "+
		"ON CREATE SET n.timestamp = {timestamp}, n.tag = {tag}, n.source = {source}", params)
	return err
}

func (n *Neo4j) insertSubdomain(data *DataOptsParams) error {
	return n.insertSub("subdomain", data)
}

func (n *Neo4j) insertSub(label string, data *DataOptsParams) error {
	params := map[string]interface{}{
		"uuid":      data.UUID,
		"timestamp": data.Timestamp,
		"sname":     data.Name,
		"sdomain":   data.Domain,
		"tag":       data.Tag,
		"source":    data.Source,
	}

	err := n.insertDomain(data)
	if err != nil {
		return err
	}

	if data.Name != data.Domain {
		_, err := n.conn.ExecNeo("MERGE (n:"+label+" {name: {sname}, enum: {uuid}}) "+
			"ON CREATE SET n.timestamp = {timestamp}, n.tag = {tag}, n.source = {source}", params)
		if err != nil {
			return err
		}

		_, err = n.conn.ExecNeo("MATCH (domain:domain {name: {sdomain}, enum: {uuid}}) "+
			"MATCH (target:"+label+" {name: {sname}, enum: {uuid}}) "+
			"MERGE (domain)-[:ROOT_OF]->(target)", params)
		if err != nil {
			return err
		}
	}
	return nil
}

func (n *Neo4j) insertCNAME(data *DataOptsParams) error {
	params := map[string]interface{}{
		"uuid":      data.UUID,
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
			UUID:      data.UUID,
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

	_, err := n.conn.ExecNeo("MATCH (source:subdomain {name: {sname}, enum: {uuid}}) "+
		"MATCH (target:subdomain {name: {tname}, enum: {uuid}}) "+
		"MERGE (source)-[:cname_to]->(target)", params)
	if err != nil {
		return err
	}

	_, err = n.conn.ExecNeo("MATCH (source:domain {name: {sname}, enum: {uuid}}) "+
		"MATCH (target:domain {name: {tname}, enum: {uuid}}) "+
		"MERGE (source)-[:cname_to]->(target)", params)
	return err
}

func (n *Neo4j) insertA(data *DataOptsParams) error {
	params := map[string]interface{}{
		"uuid":      data.UUID,
		"timestamp": data.Timestamp,
		"name":      data.Name,
		"domain":    data.Domain,
		"addr":      data.Address,
		"type":      "IPv4",
		"tag":       data.Tag,
		"source":    data.Source,
	}

	if err := n.insertSubdomain(data); err != nil {
		return err
	}

	_, err := n.conn.ExecNeo("MERGE (n:address {addr: {addr}, type: {type}, enum: {uuid}}) "+
		"ON CREATE SET n.timestamp = {timestamp}, n.tag = {tag}, n.source = {source}", params)
	if err != nil {
		return err
	}

	_, err = n.conn.ExecNeo("MATCH (source:subdomain {name: {name}, enum: {uuid}}) "+
		"MATCH (a:address {addr: {addr}, type: {type}, enum: {uuid}}) "+
		"MERGE (source)-[:a_to]->(a)", params)
	if err != nil {
		return err
	}

	_, err = n.conn.ExecNeo("MATCH (source:domain {name: {name}, enum: {uuid}}) "+
		"MATCH (a:address {addr: {addr}, type: {type}, enum: {uuid}}) "+
		"MERGE (source)-[:a_to]->(a)", params)
	return err
}

func (n *Neo4j) insertAAAA(data *DataOptsParams) error {
	params := map[string]interface{}{
		"uuid":      data.UUID,
		"timestamp": data.Timestamp,
		"name":      data.Name,
		"domain":    data.Domain,
		"addr":      data.Address,
		"type":      "IPv6",
		"tag":       data.Tag,
		"source":    data.Source,
	}

	if err := n.insertSubdomain(data); err != nil {
		return err
	}

	_, err := n.conn.ExecNeo("MERGE (n:address {addr: {addr}, type: {type}, enum: {uuid}}) "+
		"ON CREATE SET n.timestamp = {timestamp}, n.tag = {tag}, n.source = {source}", params)
	if err != nil {
		return err
	}

	_, err = n.conn.ExecNeo("MATCH (source:subdomain {name: {name}, enum: {uuid}}) "+
		"MATCH (a:address {addr: {addr}, type: {type}, enum: {uuid}}) "+
		"MERGE (source)-[:aaaa_to]->(a)", params)
	if err != nil {
		return err
	}

	_, err = n.conn.ExecNeo("MATCH (source:domain {name: {name}, enum: {uuid}}) "+
		"MATCH (a:address {addr: {addr}, type: {type}, enum: {uuid}}) "+
		"MERGE (source)-[:aaaa_to]->(a)", params)
	return err
}

func (n *Neo4j) insertPTR(data *DataOptsParams) error {
	params := map[string]interface{}{
		"uuid":      data.UUID,
		"timestamp": data.Timestamp,
		"name":      data.Name,
		"domain":    data.Domain,
		"target":    data.TargetName,
		"tag":       data.Tag,
		"source":    data.Source,
	}

	err := n.insertSubdomain(&DataOptsParams{
		UUID:      data.UUID,
		Timestamp: data.Timestamp,
		Name:      data.TargetName,
		Domain:    data.Domain,
		Tag:       data.Tag,
		Source:    data.Source,
	})
	if err != nil {
		return err
	}

	_, err = n.conn.ExecNeo("MERGE (n:ptr {name: {name}, enum: {uuid}}) "+
		"ON CREATE SET n.timestamp = {timestamp}, n.tag = {tag}, n.source = {source}", params)
	if err != nil {
		return err
	}

	_, err = n.conn.ExecNeo("MATCH (p:ptr {name: {name}, enum: {uuid}}), "+
		"(t:subdomain {name: {target}, enum: {uuid}}) "+
		"MERGE (p)-[:ptr_to]->(t)", params)
	if err != nil {
		return err
	}

	_, err = n.conn.ExecNeo("MATCH (p:ptr {name: {name}, enum: {uuid}}), "+
		"(t:domain {name: {target}, enum: {uuid}}) "+
		"MERGE (p)-[:ptr_to]->(t)", params)
	return err
}

func (n *Neo4j) insertSRV(data *DataOptsParams) error {
	params := map[string]interface{}{
		"uuid":      data.UUID,
		"timestamp": data.Timestamp,
		"name":      data.Name,
		"domain":    data.Domain,
		"service":   data.Service,
		"target":    data.TargetName,
		"tag":       data.Tag,
		"source":    data.Source,
	}

	if err := n.insertSubdomain(data); err != nil {
		return err
	}

	err := n.insertSubdomain(&DataOptsParams{
		UUID:      data.UUID,
		Timestamp: data.Timestamp,
		Name:      data.Service,
		Domain:    data.Domain,
		Tag:       data.Tag,
		Source:    data.Source,
	})
	if err != nil {
		return err
	}

	err = n.insertSubdomain(&DataOptsParams{
		UUID:      data.UUID,
		Timestamp: data.Timestamp,
		Name:      data.TargetName,
		Domain:    data.Domain,
		Tag:       data.Tag,
		Source:    data.Source,
	})
	if err != nil {
		return err
	}

	_, err = n.conn.ExecNeo("MATCH (srv:subdomain {name: {service}, enum: {uuid}}), "+
		"(source:subdomain {name: {name}, enum: {uuid}}) "+
		"MERGE (srv)-[:service_for]->(source)", params)
	if err != nil {
		return err
	}

	_, err = n.conn.ExecNeo("MATCH (srv:subdomain {name: {service}, enum: {uuid}}), "+
		"(source:domain {name: {name}, enum: {uuid}}) "+
		"MERGE (srv)-[:service_for]->(source)", params)
	if err != nil {
		return err
	}

	_, err = n.conn.ExecNeo("MATCH (srv:subdomain {name: {service}, enum: {uuid}}), "+
		"(target:subdomain {name: {target}, enum: {uuid}}) "+
		"MERGE (srv)-[:srv_to]->(target)", params)
	return err
}

func (n *Neo4j) insertNS(data *DataOptsParams) error {
	params := map[string]interface{}{
		"uuid":      data.UUID,
		"timestamp": data.Timestamp,
		"name":      data.Name,
		"domain":    data.Domain,
		"target":    data.TargetName,
		"tdomain":   data.TargetDomain,
		"tag":       data.Tag,
		"source":    data.Source,
	}

	if err := n.insertSubdomain(data); err != nil {
		return err
	}

	err := n.insertSub("ns", &DataOptsParams{
		UUID:      data.UUID,
		Timestamp: data.Timestamp,
		Name:      data.TargetName,
		Domain:    data.TargetDomain,
		Tag:       data.Tag,
		Source:    data.Source,
	})
	if err != nil {
		return err
	}

	_, err = n.conn.ExecNeo("MATCH (source:subdomain {name: {name}, enum: {uuid}}) "+
		"MATCH (nameserver:ns {name: {target}, enum: {uuid}}) "+
		"MERGE (source)-[:ns_to]->(nameserver)", params)
	if err != nil {
		return err
	}

	_, err = n.conn.ExecNeo("MATCH (source:domain {name: {name}, enum: {uuid}}) "+
		"MATCH (nameserver:ns {name: {target}, enum: {uuid}}) "+
		"MERGE (source)-[:ns_to]->(nameserver)", params)
	return err
}

func (n *Neo4j) insertMX(data *DataOptsParams) error {
	params := map[string]interface{}{
		"uuid":      data.UUID,
		"timestamp": data.Timestamp,
		"name":      data.Name,
		"domain":    data.Domain,
		"target":    data.TargetName,
		"tdomain":   data.TargetDomain,
		"tag":       data.Tag,
		"source":    data.Source,
	}

	if err := n.insertSubdomain(data); err != nil {
		return err
	}

	err := n.insertSub("mx", &DataOptsParams{
		UUID:      data.UUID,
		Timestamp: data.Timestamp,
		Name:      data.TargetName,
		Domain:    data.TargetDomain,
		Tag:       data.Tag,
		Source:    data.Source,
	})
	if err != nil {
		return err
	}

	_, err = n.conn.ExecNeo("MATCH (source:subdomain {name: {name}, enum: {uuid}}) "+
		"MATCH (mailserver:mx {name: {target}, enum: {uuid}}) "+
		"MERGE (source)-[:mx_to]->(mailserver)", params)
	if err != nil {
		return err
	}

	_, err = n.conn.ExecNeo("MATCH (source:domain {name: {name}, enum: {uuid}}) "+
		"MATCH (mailserver:mx {name: {target}, enum: {uuid}}) "+
		"MERGE (source)-[:ns_to]->(mailserver)", params)
	return err
}

func (n *Neo4j) insertInfrastructure(data *DataOptsParams) error {
	params := map[string]interface{}{
		"uuid":      data.UUID,
		"timestamp": data.Timestamp,
		"addr":      data.Address,
		"asn":       data.ASN,
		"cidr":      data.CIDR,
		"desc":      data.Description,
	}

	_, err := n.conn.ExecNeo("MERGE (n:netblock {cidr: {cidr}, enum: {uuid}}) "+
		"ON CREATE SET n.timestamp = {timestamp}", params)
	if err != nil {
		return err
	}

	_, err = n.conn.ExecNeo("MATCH (a:address {addr: {addr}, enum: {uuid}}) "+
		"MATCH (nb:netblock {cidr: {cidr}, enum: {uuid}}) "+
		"MERGE (nb)-[:contains]->(a)", params)
	if err != nil {
		return err
	}

	_, err = n.conn.ExecNeo("MERGE (n:as {asn: {asn}, enum: {uuid}}) "+
		"ON CREATE SET n.desc = {desc}, n.timestamp = {timestamp}", params)
	if err != nil {
		return err
	}

	_, err = n.conn.ExecNeo("MATCH (a:as {asn: {asn}, enum: {uuid}}) "+
		"MATCH (nb:netblock {cidr: {cidr}, enum: {uuid}}) "+
		"MERGE (a)-[:has_prefix]->(nb)", params)
	return err
}
