// SPDX-License-Identifier: Apache-2.0
// Package oamrepo connects the AI graph tools to the existing Amass repository.
package oamrepo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/ai"
	"github.com/owasp-amass/asset-db/repository"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

type Adapter struct {
	Repo repository.Repository
	Aliases []ai.OrganizationAlias
}

func (a Adapter) GetAsset(ctx context.Context, id string) (ai.Asset, error) {
	if a.Repo == nil {
		return ai.Asset{}, errors.New("missing OAM repository")
	}
	ent, err := a.Repo.FindEntityById(ctx, id)
	if err != nil {
		return ai.Asset{}, err
	}
	return convert(ent)
}
func convert(e *dbt.Entity) (ai.Asset, error) {
	if e == nil || e.Asset == nil {
		return ai.Asset{}, errors.New("empty entity/asset")
	}
	return ai.Asset{ID: e.ID, Type: string(e.Asset.AssetType()), Key: e.Asset.Key(),
		Content: e.Asset, CreatedAt: e.CreatedAt, LastSeen: e.LastSeen}, nil
}
func knownAssetType(t string) bool {
	for _, item := range oam.AssetList {
		if string(item) == t {
			return true
		}
	}
	return false
}
func (a Adapter) FindAssets(ctx context.Context, t string, since time.Time, limit int) ([]ai.Asset, error) {
	if !knownAssetType(t) {
		return nil, fmt.Errorf("unknown OAM asset type %q", t)
	}
	ents, err := a.Repo.FindEntitiesByType(ctx, oam.AssetType(t), since, limit)
	if err != nil {
		return nil, err
	}
	if len(ents) > limit {
		ents = ents[:limit]
	}
	out := make([]ai.Asset, 0, len(ents))
	for _, ent := range ents {
		v, err := convert(ent)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (a Adapter) Edges(ctx context.Context, id, direction, label string, since time.Time) ([]ai.Relation, error) {
	ent, err := a.Repo.FindEntityById(ctx, id)
	if err != nil {
		return nil, err
	}
	var labels []string
	if label != "" {
		labels = []string{label}
	}
	var found []ai.Relation
	convertEdges := func(edges []*dbt.Edge, dir string) error {
		for _, edge := range edges {
			if edge == nil || edge.Relation == nil || edge.FromEntity == nil || edge.ToEntity == nil {
				return errors.New("invalid edge")
			}
			if label != "" && edge.Relation.Label() != label {
				continue
			}
			found = append(found, ai.Relation{ID: edge.ID, FromID: edge.FromEntity.ID, ToID: edge.ToEntity.ID,
				Label: edge.Relation.Label(), Type: string(edge.Relation.RelationType()), Direction: dir,
				CreatedAt: edge.CreatedAt, LastSeen: edge.LastSeen})
		}
		return nil
	}
	if direction == "in" || direction == "both" {
		edges, err := a.Repo.IncomingEdges(ctx, ent, since, labels...)
		if err != nil {
			return nil, err
		}
		if err := convertEdges(edges, "in"); err != nil {
			return nil, err
		}
	}
	if direction == "out" || direction == "both" {
		edges, err := a.Repo.OutgoingEdges(ctx, ent, since, labels...)
		if err != nil {
			return nil, err
		}
		if err := convertEdges(edges, "out"); err != nil {
			return nil, err
		}
	}
	return found, nil
}
func (a Adapter) Evidence(ctx context.Context, id string, limit int) ([]ai.Evidence, error) {
	if ent, err := a.Repo.FindEntityById(ctx, id); err == nil {
		tags, err := a.Repo.FindEntityTags(ctx, ent, time.Time{})
		if emptyTagLookup(err) {return []ai.Evidence{},nil}
		if err != nil {return nil,err}
		out := make([]ai.Evidence, 0)
		for _, tag := range tags {
			if tag == nil || tag.Property == nil {
				continue
			}
			if len(out) >= limit {
				break
			}
			out = append(out, ai.Evidence{ID: tag.ID, SubjectID: id, SourceID: source(tag.Property),
				Kind: string(tag.Property.PropertyType()), Property: tag.Property, LastSeen: tag.LastSeen})
		}
		return out, nil
	}
	edge, err := a.Repo.FindEdgeById(ctx, id)
	if err != nil {
		return nil, err
	}
	tags, err := a.Repo.FindEdgeTags(ctx, edge, time.Time{})
	if emptyTagLookup(err) {return []ai.Evidence{},nil}
	if err != nil {return nil,err}
	out := make([]ai.Evidence, 0)
	for _, tag := range tags {
		if tag == nil || tag.Property == nil {
			continue
		}
		if len(out) >= limit {
			break
		}
		out = append(out, ai.Evidence{ID: tag.ID, SubjectID: id, SourceID: source(tag.Property),
			Kind: string(tag.Property.PropertyType()), Property: tag.Property, LastSeen: tag.LastSeen})
	}
	return out, nil
}

// emptyTagLookup recognizes only exact repository-specific empty-result
// messages. Asset Database currently returns ordinary errors for missing
// tags instead of a shared sentinel. Do NOT treat arbitrary lookup errors
// as absence: storage, authentication, and decoding failures remain fatal.
func emptyTagLookup(err error) bool {
 if err==nil {return false}
 switch strings.TrimSpace(err.Error()) {
 case "no tags found for edge", // sqlite
      "no tags found for entity", // postgres (edge-tag reader)
      "no edge tags found", // neo4j
      "zero tags found": // neo4j
  return true
 }
 return false
}

// EdgeEvidence always queries the relation namespace. Entity and edge
// identifiers may be identical; a generic FindEntityById-first lookup cannot
// safely be used for source-level relationship attribution.
func (a Adapter) EdgeEvidence(ctx context.Context,id string,limit int)([]ai.Evidence,error){
 if a.Repo==nil{return nil,errors.New("missing OAM repository")}
 if id==""||limit<1||limit>500{return nil,errors.New("invalid edge evidence query or limit")}
 edge,err:=a.Repo.FindEdgeById(ctx,id)
 if err!=nil{return nil,fmt.Errorf("resolve exact edge for evidence: %w",err)}
 tags,err:=a.Repo.FindEdgeTags(ctx,edge,time.Time{})
 if emptyTagLookup(err) {
  return []ai.Evidence{},nil
 }
 if err!=nil{return nil,fmt.Errorf("read edge %s provenance tags: %w",id,err)}
 out:=make([]ai.Evidence,0,min(len(tags),limit))
 for _,tag:=range tags{
  if tag==nil||tag.Property==nil{continue}
  if len(out)>=limit{break}
  out=append(out,ai.Evidence{ID:tag.ID,SubjectID:id,SourceID:source(tag.Property),
   Kind:string(tag.Property.PropertyType()),Property:tag.Property,LastSeen:tag.LastSeen})
 }
 return out,nil
}

var _ ai.EdgeEvidenceReader = Adapter{}

// Source identity is only assigned to explicitly typed provenance properties.
// Other properties are evidence but do not establish independent sources.
func source(p oam.Property) string {
	if p.PropertyType() != oam.SourceProperty {
		return ""
	}
	return p.Name()
}

var _ ai.Graph = Adapter{}

// AllowedRelation ensures that an inferred edge conforms to the existing OAM taxonomy.
func AllowedRelation(subject, label, object string) bool {
	// AI proposes SimpleRelation only in this initial implementation.
	return oam.ValidRelationship(oam.AssetType(subject), label, oam.SimpleRelation, oam.AssetType(object))
}

// EdgesLimited requires a repository that implements server-side SQL bounds.
// The current released asset-db dependency may not implement it yet; graph
// walks must fail closed until the bounded API is released or pinned.
func (a Adapter) EdgesLimited(ctx context.Context, id, direction, label string, since time.Time, limit int) ([]ai.Relation, bool, error) {
	if a.Repo == nil {
		return nil, false, errors.New("missing repository")
	}
	bounded, ok := a.Repo.(interface {
		ReadEdgesLimited(context.Context, *dbt.Entity, string, time.Time, int, ...string) ([]*dbt.Edge, bool, error)
	})
	if !ok {
		return nil, false, errors.New("asset-db version lacks bounded edge reader; upgrade the repository dependency")
	}
	ent, err := a.Repo.FindEntityById(ctx, id)
	if err != nil {
		return nil, false, err
	}
	var labels []string
	if label != "" {
		labels = []string{label}
	}
	edges, more, err := bounded.ReadEdgesLimited(ctx, ent, direction, since, limit, labels...)
	if err != nil {
		return nil, false, err
	}
	if len(edges) > limit {
		return nil, false, errors.New("repository violated bounded edge limit")
	}
	out := make([]ai.Relation, 0, len(edges))
	for _, e := range edges {
		if e == nil || e.Relation == nil || e.FromEntity == nil || e.ToEntity == nil {
			return nil, false, errors.New("malformed bounded edge")
		}
		dir := "out"
		if e.ToEntity.ID == id {
			dir = "in"
		}
		out = append(out, ai.Relation{ID: e.ID, FromID: e.FromEntity.ID, ToID: e.ToEntity.ID, Label: e.Relation.Label(), Type: string(e.Relation.RelationType()), Direction: dir, CreatedAt: e.CreatedAt, LastSeen: e.LastSeen})
	}
	return out, more, nil
}

var _ ai.BoundedGraph = Adapter{}


// LookupOrganizations performs bounded, typed lookups with a conservative
// punctuation fallback. It never scans the repository, and never silently
// selects among multiple plausible legal entities.
func (a Adapter) LookupOrganizations(ctx context.Context, name string, limit int) ([]ai.Asset, error) {
	if a.Repo == nil {
		return nil, errors.New("missing OAM repository")
	}
	name = strings.Join(strings.Fields(name), " ")
	if name == "" || len(name) > 256 || limit < 1 || limit > 10 {
		return nil, errors.New("invalid organization lookup parameters")
	}

	// Models sometimes remove a final period from a company name (e.g.,
	// "Inc." -> "Inc"). Try both exact forms using indexed content queries.
	// This is intentionally not fuzzy matching: other punctuation and
	// arbitrary string similarity are NOT accepted as an entity identity.
	variants := []string{name}
	if strings.HasSuffix(name, ".") {
		variants = append(variants, strings.TrimSuffix(name, "."))
	} else {
		variants = append(variants, name+".")
	}

	out := make([]ai.Asset, 0, limit)
	seen := make(map[string]bool, limit)
	for _, candidate := range variants {
		if candidate == "" || len(out) >= limit {
			break
		}
		remaining := limit - len(out)
		entities, err := a.Repo.FindEntitiesByContent(ctx, oam.Organization,
			time.Time{}, remaining, dbt.ContentFilters{"name": candidate})
		if err != nil {
			// PostgreSQL reports an empty content query as a sentinel error.
			// Other repository failures must never be mistaken for no matches.
			if strings.TrimSpace(err.Error()) == "zero entities found" {
				continue
			}
			return nil, err
		}
		if len(entities) > remaining {
			return nil, errors.New("repository exceeded organization lookup limit")
		}
		for _, entity := range entities {
			asset, err := convert(entity)
			if err != nil {
				return nil, err
			}
			if !seen[asset.ID] {
				seen[asset.ID] = true
				out = append(out, asset)
			}
		}
	}
	return out, nil
}


// ResolveOrganizations generates field-specific candidate matches using only
// bounded repository content filters. Alias metadata must be explicitly supplied
// from a curated source; neither aliases nor names imply legal ownership.
func (a Adapter) ResolveOrganizations(ctx context.Context, query ai.OrganizationQuery, limit int) (ai.OrganizationResolution, error) {
    result:=ai.OrganizationResolution{Query:query,Candidates:[]ai.OrganizationCandidate{},Status:"not_found"}
    if a.Repo==nil {return result,errors.New("missing OAM repository")}
    if err:=query.Validate();err!=nil {return result,err}
    if limit<1 || limit>10 {return result,errors.New("candidate limit must be 1..10")}

    // Exact database lookup only. A second bounded query permits a
    // terminal-period variant, which models frequently omit. Fuzzy
    // similarity, suffix removal and unrestricted table scans are prohibited.
    variants:=func(s string) []string {
        s=strings.Join(strings.Fields(s)," ")
        if strings.HasSuffix(s,".") {return []string{s,strings.TrimSuffix(s,".")}}
        return []string{s,s+"."}
    }
    matches:=map[string]*ai.OrganizationCandidate{}
    tooMany:=false
    add:=func(ent *dbt.Entity,field,value,source string) error {
        asset,err:=convert(ent)
        if err!=nil {return err}
        // Make jurisdiction a strict identity constraint if supplied.
        var org oamorg.Organization
        raw,err:=json.Marshal(asset.Content)
        if err!=nil {return err}
        if err:=json.Unmarshal(raw,&org);err!=nil {return err}
        if query.Jurisdiction!="" && org.Jurisdiction!=query.Jurisdiction {return nil}
        c,exists:=matches[asset.ID]
        if !exists {
            if len(matches)>=limit {
                tooMany=true
                return nil
            }
            c=&ai.OrganizationCandidate{Asset:asset,Matches:[]ai.ResolutionMatch{}}
            matches[asset.ID]=c
        }
        for _,m:=range c.Matches {
            if m.Field==field && m.Value==value && m.Source==source {return nil}
        }
        c.Matches=append(c.Matches,ai.ResolutionMatch{Field:field,Value:value,Source:source})
        return nil
    }
    queryBy:=func(field,value,source string) error {
        filters:=dbt.ContentFilters{field:value}
        if field=="registration_id" {filters["jurisdiction"]=query.Jurisdiction}
        // Each lookup requests one extra candidate for truncation detection.
        // Any overflow prevents automatic selection.
        rows,err:=a.Repo.FindEntitiesByContent(ctx,oam.Organization,time.Time{},limit+1,filters)
        if err!=nil {
            if strings.TrimSpace(err.Error())=="zero entities found" {return nil}
            return err
        }
        if len(rows)>limit {tooMany=true}
        for _,ent:=range rows {
            if err:=add(ent,field,value,source);err!=nil {return err}
        }
        return nil
    }
    switch {
    case query.UniqueID!="":
        if err:=queryBy("unique_id",query.UniqueID,"");err!=nil{return result,err}
    case query.RegistrationID!="":
        if err:=queryBy("registration_id",query.RegistrationID,"");err!=nil{return result,err}
    case query.LegalName!="":
        for _,v:=range variants(query.LegalName) {
            if err:=queryBy("legal_name",v,"");err!=nil{return result,err}
        }
    case query.Name!="":
        for _,v:=range variants(query.Name) {
            for _,field:=range []string{"name","legal_name"} {
                if err:=queryBy(field,v,"");err!=nil{return result,err}
            }
        }
        // Resolve explicitly documented trade or historic aliases only.
        // Alias rows point to an existing OAM unique_id; their source is
        // returned in the candidate provenance. No alias is auto-created.
        for _,alias:=range a.Aliases {
            if ai.NormalizeOrganizationAlias(alias.Alias)!=ai.NormalizeOrganizationAlias(query.Name) {continue}
            if query.Jurisdiction!="" && alias.Jurisdiction!="" && alias.Jurisdiction!=query.Jurisdiction {continue}
            if err:=queryByAlias(alias,add,ctx,a.Repo,limit);err!=nil{return result,err}
        }
    }
    for _,candidate:=range matches {result.Candidates=append(result.Candidates,*candidate)}
    sort.Slice(result.Candidates,func(i,j int)bool{return result.Candidates[i].Asset.ID<result.Candidates[j].Asset.ID})
    for i:=range result.Candidates {
        sort.Slice(result.Candidates[i].Matches,func(j,k int)bool{
            a,b:=result.Candidates[i].Matches[j],result.Candidates[i].Matches[k]
            if a.Field!=b.Field{return a.Field<b.Field}
            if a.Value!=b.Value{return a.Value<b.Value}
            return a.Source<b.Source
        })
    }
    switch {
    case tooMany: result.Status="truncated";result.Truncated=true
    case len(result.Candidates)==0:result.Status="not_found"
    case len(result.Candidates)==1:result.Status="matched"
    default: result.Status="ambiguous"
    }
    return result,nil
}

// Alias-specific lookup retains the actual curated source rather than
// mislabeling an alias as a database-exact name match.
func queryByAlias(alias ai.OrganizationAlias,
    add func(*dbt.Entity,string,string,string)error, ctx context.Context,
    repo repository.Repository, limit int) error {
    rows,err:=repo.FindEntitiesByContent(ctx,oam.Organization,time.Time{},limit+1,dbt.ContentFilters{"unique_id":alias.UniqueID})
    if err!=nil {
        if strings.TrimSpace(err.Error())=="zero entities found" {return nil}
        return err
    }
    for _,ent:=range rows {
        // An alias jurisdiction must agree with the actual OAM entity.
        if alias.Jurisdiction!="" {
            org,ok:=ent.Asset.(*oamorg.Organization)
            if !ok{return errors.New("alias target is not an Organization")}
            if org.Jurisdiction!=alias.Jurisdiction {continue}
        }
        if err:=add(ent,"alias",alias.Alias,alias.Source);err!=nil{return err}
    }
    return nil
}

var _ ai.OrganizationResolver = Adapter{}

var _ ai.OrganizationLookup = Adapter{}


// Catalog derives permitted graph transitions from the OAM package.
type Catalog struct{}

// Relations enumerates actual OAM labels and relation types. Sorted so
// different providers and runs receive the same schema context.
func (Catalog) Relations() []ai.RelationshipSchema {
	var results []ai.RelationshipSchema
	for _, src := range oam.AssetList {
		for _, label := range oam.GetAssetOutgoingRelations(src) {
			for _, relType := range oam.RelationList {
				for _, dst := range oam.GetTransformAssetTypes(src, label, relType) {
					results = append(results, ai.RelationshipSchema{
						SourceType: string(src), Label: label,
						RelationType: string(relType), DestinationType: string(dst),
					})
				}
			}
		}
	}
	sort.Slice(results, func(i, j int) bool {
		a, b := results[i], results[j]
		if a.SourceType != b.SourceType { return a.SourceType < b.SourceType }
		if a.Label != b.Label { return a.Label < b.Label }
		if a.RelationType != b.RelationType { return a.RelationType < b.RelationType }
		return a.DestinationType < b.DestinationType
	})
	return results
}

var _ ai.SchemaCatalog = Catalog{}

// SearchFields enumerates indexed typed selectors for each OAM asset kind.
// These keys follow the Asset Database content-filter registries.
// ContactRecord currently has only discovered_at, a non-identity timestamp:
// use an explicit entity_id for reliable lookup.
func (Catalog) SearchFields() []ai.AssetSearchSchema {
    filters:=map[string][]string{
        "Account":{"unique_id","account_type","username","account_number"},
        "AutnumRecord":{"number","handle","name","whois_server"},
        "AutonomousSystem":{"number"},
        "ContactRecord":{},
        "DomainRecord":{"domain","name","extension","punycode","id","whois_server"},
        "File":{"url","name","type"},
        "FQDN":{"name"},
        "FundsTransfer":{"unique_id","amount","reference_number"},
        "Identifier":{"unique_id","id","id_type"},
        "IPAddress":{"address"},
        "IPNetRecord":{"cidr","handle","name","start_address","end_address","whois_server","parent_handle"},
        "Location":{"address","building","building_number","province","street_name","unit","locality","city","country","postal_code"},
        "Netblock":{"cidr"},
        "Organization":{"unique_id","name","legal_name","registration_id","jurisdiction"},
        "Person":{"unique_id","full_name","first_name","family_name"},
        "Phone":{"e164","country_code"},
        "Product":{"unique_id","product_name","product_type"},
        "ProductRelease":{"name"},
        "Service":{"unique_id","service_type"},
        "TLSCertificate":{"serial_number","subject_common_name"},
        "URL":{"url","scheme"},
    }
    out:=make([]ai.AssetSearchSchema,0,len(oam.AssetList))
    for _,t:=range oam.AssetList {
        fields,ok:=filters[string(t)]
        if !ok {continue}
        out=append(out,ai.AssetSearchSchema{Type:string(t),Fields:fields})
    }
    return out
}
var _ ai.AssetSearchCatalog = Catalog{}

// ResolveAsset requires a registered typed selector, uses only bounded read
// APIs, and never silently resolves an ambiguous query to its first result.
func (a Adapter) ResolveAsset(ctx context.Context, selector ai.AssetSelector, limit int)(ai.AssetResolution,error){
    result:=ai.AssetResolution{Query:selector,Status:"not_found",Candidates:[]ai.OrganizationCandidate{}}
    if a.Repo==nil{return result,errors.New("missing OAM repository")}
    if err:=selector.Validate((Catalog{}).SearchFields());err!=nil{return result,err}
    if limit<1 || limit>10{return result,errors.New("asset resolution limit must be 1..10")}
    if selector.EntityID!="" {
        asset,err:=a.GetAsset(ctx,selector.EntityID)
        if err!=nil {
            // Invalid or inaccessible IDs are errors, not negative evidence.
            return result,fmt.Errorf("resolve entity_id: %w",err)
        }
        if asset.Type!=selector.Type {return result,errors.New("entity_id does not match asserted OAM type")}
        result.Candidates=append(result.Candidates,ai.OrganizationCandidate{
            Asset:asset,Matches:[]ai.ResolutionMatch{{Field:"entity_id",Value:selector.EntityID}},
        })
        result.Status="matched"
        return result,nil
    }
    value:=selector.Value
    if selector.Type=="FQDN" && selector.Field=="name" {
        value=strings.ToLower(strings.TrimSuffix(value,"."))
    }
    // The repository uses a bounded indexed query. Ask for one extra record
    // so a capped result can never masquerade as a unique result.
    filter:=dbt.ContentFilters{selector.Field:value}
    rows,err:=a.Repo.FindEntitiesByContent(ctx,oam.AssetType(selector.Type),time.Time{},limit+1,filter)
    if err!=nil {
        if strings.TrimSpace(err.Error())=="zero entities found" {return result,nil}
        return result,err
    }
    if len(rows)>limit {result.Truncated=true}
    for _,ent:=range rows {
        if len(result.Candidates)>=limit {break}
        asset,err:=convert(ent)
        if err!=nil{return result,err}
        if asset.Type!=selector.Type{return result,errors.New("repository returned wrong OAM type")}
        result.Candidates=append(result.Candidates,ai.OrganizationCandidate{
            Asset:asset,Matches:[]ai.ResolutionMatch{{Field:selector.Field,Value:value}},
        })
    }
    sort.Slice(result.Candidates,func(i,j int)bool{return result.Candidates[i].Asset.ID<result.Candidates[j].Asset.ID})
    switch {
    case result.Truncated:result.Status="truncated"
    case len(result.Candidates)==0:result.Status="not_found"
    case len(result.Candidates)==1:result.Status="matched"
    default:result.Status="ambiguous"
    }
    return result,nil
}
var _ ai.AssetResolver = Adapter{}
