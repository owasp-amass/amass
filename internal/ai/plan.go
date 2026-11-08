// SPDX-License-Identifier: Apache-2.0
package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const maxPlanHops = 3

// TypedPlan is the model-independent, read-only intermediate representation.
// The model selects among OAM transitions; Go validates the entire plan.
type TypedPlan struct {
	Subject PlanSubject `json:"subject"`
	Hops []PlanHop `json:"hops"`
}
type PlanSubject struct {
	Type string `json:"type"`
	Name string `json:"name,omitempty"`
	LegalName string `json:"legal_name,omitempty"`
	UniqueID string `json:"unique_id,omitempty"`
	RegistrationID string `json:"registration_id,omitempty"`
	Jurisdiction string `json:"jurisdiction,omitempty"`
}
func (s PlanSubject) OrganizationQuery() OrganizationQuery {
	return OrganizationQuery{Name:s.Name,LegalName:s.LegalName,UniqueID:s.UniqueID,RegistrationID:s.RegistrationID,Jurisdiction:s.Jurisdiction}
}
type PlanHop struct {
	Direction string `json:"direction"`
	Label string `json:"label"`
	RelationType string `json:"relation_type"`
	DestinationType string `json:"destination_type"`
}
type PlanMatch struct {
	Nodes []Asset `json:"nodes"`
	Edges []Relation `json:"edges"`
}
type partialPath struct {
	nodes []Asset
	edges []Relation
}

// validatePlan accepts only transitions explicitly present in the catalog.
// An unknown semantic label is never treated as a negative query result.
func validatePlan(plan TypedPlan, catalog []RelationshipSchema, limits Limits) error {
	if plan.Subject.Type != "Organization" {
		return errors.New("current planner supports Organization starting entities only")
	}
	if err:=plan.Subject.OrganizationQuery().Validate();err!=nil {return fmt.Errorf("invalid subject: %w",err)}
	if len(plan.Hops) < 1 || len(plan.Hops) > maxPlanHops || len(plan.Hops) > limits.MaxDepth {
		return errors.New("plan must contain 1..3 bounded graph hops")
	}
	current := plan.Subject.Type
	for i, step := range plan.Hops {
		if step.Direction != "out" && step.Direction != "in" {
			return fmt.Errorf("hop %d direction must be out or in", i+1)
		}
		found := false
		for _, rel := range catalog {
			if step.Label != rel.Label || step.RelationType != rel.RelationType {
				continue
			}
			if step.Direction == "out" && current == rel.SourceType && step.DestinationType == rel.DestinationType ||
				step.Direction == "in" && current == rel.DestinationType && step.DestinationType == rel.SourceType {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("hop %d is not permitted by the OAM taxonomy: %s %s %s -> %s (%s)",
				i+1, current, step.Direction, step.Label, step.DestinationType, step.RelationType)
		}
		current = step.DestinationType
	}
	return nil
}

func parseTypedPlan(raw string) (TypedPlan, error) {
	var plan TypedPlan
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "\x60\x60\x60") {
		raw = strings.TrimPrefix(raw, "\x60\x60\x60json")
		raw = strings.TrimPrefix(raw, "\x60\x60\x60")
		raw = strings.TrimSuffix(strings.TrimSpace(raw), "\x60\x60\x60")
	}
	if err := decodeStrict([]byte(strings.TrimSpace(raw)), &plan); err != nil {
		return plan, fmt.Errorf("model did not return a valid typed JSON plan: %w", err)
	}
	return plan, nil
}

func (a Agent) planQuestion(ctx context.Context, question string) (TypedPlan, error) {
	var zero TypedPlan
	if a.Runner.Catalog == nil {
		return zero, errors.New("OAM schema catalog is unavailable")
	}
	catalog := a.Runner.Catalog.Relations()
	rawCatalog, err := json.Marshal(catalog)
	if err != nil { return zero, err }
	system := "You are an OWASP Open Asset Model query planner. Return ONLY a JSON object, without markdown, matching " +
		"{\"subject\":{\"type\":\"Organization\",\"name\":\"EXACT company name\"},\"hops\":[{\"direction\":\"out\",\"label\":\"exact OAM label\",\"relation_type\":\"exact OAM relation type\",\"destination_type\":\"exact OAM asset type\"}]}. " +
		"Treat the request as an investigation over STORED graph relationships, not general knowledge. " +
		"Only choose transitions appearing in the catalog. Each hop begins at the previous hop's destination type. " +
		"For incoming hops reverse the permitted source/destination types. Prefer the shortest meaningful path (maximum 3 hops). " +
		"Subject type must be Organization. Specify exactly one of name, legal_name, unique_id, registration_id. " +
		"Use legal_name only for explicitly stated legal names, unique_id only for explicitly stated OAM IDs, and registration_id only when both registration number and jurisdiction are given. " +
		"Preserve the user-supplied organization string without inventing suffixes, aliases or jurisdictions. " +
		"Do not invent labels or add confidence claims. If you cannot construct a valid plan, return empty hops. " +
		"OAM RELATIONSHIP CATALOG: " + string(rawCatalog)
	conversation := []Message{{Role:"system",Text:system},{Role:"user",Text:question}}
	for attempt:=0; attempt<2; attempt++ {
		response, err := a.Model.Generate(ctx, conversation, nil)
		if err != nil {return zero, err}
		if len(response.Calls)>0 {return zero, errors.New("planner attempted a tool call instead of returning typed JSON")}
		plan, err := parseTypedPlan(response.Text)
		if err==nil {err=validatePlan(plan,catalog,a.Runner.Limits)}
		if err==nil {return plan,nil}
		if attempt==1 {return zero, fmt.Errorf("unable to produce valid OAM query plan: %w",err)}
		conversation=append(conversation,Message{Role:"assistant",Text:response.Text},
			Message{Role:"user",Text:"That proposed plan is invalid: "+err.Error()+". Correct the plan using only the OAM relationship catalog, with exact labels, directions and destination types. Output JSON only."})
	}
	return zero, errors.New("query planner exhausted correction attempts")
}

// AskPlanned always validates a typed plan before touching the Asset Database.
// It does not use phrase matching or trust model-generated relationship claims.
func (a Agent) AskPlanned(ctx context.Context, question string) (Investigation, error) {
	var out Investigation
	if a.Model==nil || a.Runner.Graph==nil || a.Runner.Catalog==nil {
		return out, errors.New("model, graph, and schema catalog are required")
	}
	if err:=a.Runner.Limits.Validate();err!=nil{return out,err}
	plan,err:=a.planQuestion(ctx,question)
	if err!=nil {out.Incomplete=true;return out,err}
	out.Plan=&plan
	lookupJSON,_:=json.Marshal(struct{
		OrganizationQuery
		Limit int `json:"limit"`
	}{OrganizationQuery:plan.Subject.OrganizationQuery(),Limit:10})
	raw,err:=a.Runner.Run(ctx,"resolve_organization",lookupJSON)
	if err!=nil {out.Incomplete=true;return out,fmt.Errorf("organization lookup failed: %w",err)}
	out.ToolCalls++
	out.Observations=append(out.Observations,Observation{Tool:"resolve_organization",CallID:"planned-root",Result:string(raw)})
	var resolution OrganizationResolution
	if err:=json.Unmarshal(raw,&resolution);err!=nil{return out,fmt.Errorf("decode organization resolution: %w",err)}
	out.Resolution=&resolution
	if resolution.Status!="matched" || len(resolution.Candidates)!=1 {
		out.Incomplete=true
		switch resolution.Status {
		case "not_found": out.Answer="No Organization matched the asserted name or identifier in the current Asset Database; no relationship conclusion can be drawn."
		case "ambiguous":
			var names []string
			for _,c:=range resolution.Candidates {
				var sources []string
				for _,m:=range c.Matches {if m.Source!="" {sources=append(sources,m.Field+"="+m.Value+" [source: "+m.Source+"]")} else {sources=append(sources,m.Field+"="+m.Value)}}
				names=append(names,humanAsset(c.Asset)+" ["+strings.Join(sources,", ")+"]")
			}
			out.Answer="Multiple Organization candidates matched; specify an explicit unique_id or jurisdiction-qualified registration_id. Candidates: "+strings.Join(names,"; ")
		case "truncated":out.Answer="Organization candidates exceeded the bounded resolution limit; cannot safely select an identity."
		default:return out,fmt.Errorf("unrecognized organization resolution status %q",resolution.Status)
		}
		return out,nil
	}
	paths:=[]partialPath{{nodes:[]Asset{resolution.Candidates[0].Asset}}}
	edgesSeen:=map[string]bool{}
	nodesSeen:=map[string]bool{resolution.Candidates[0].Asset.ID:true}
	for hopIndex,step:=range plan.Hops {
		next:=make([]partialPath,0)
		for _,path:=range paths {
			if out.ToolCalls>=a.Runner.Limits.MaxToolCalls {
				out.Incomplete=true
				out.Answer="Graph query stopped at its tool-call budget; no complete result can be asserted."
				return out,nil
			}
			startID:=path.nodes[len(path.nodes)-1].ID
			req,_:=json.Marshal(WalkRequest{StartID:startID,Direction:step.Direction,Label:step.Label,Depth:1})
			walkRaw,err:=a.Runner.Run(ctx,"walk_relations",req)
			if err!=nil {out.Incomplete=true;return out,fmt.Errorf("hop %d traversal failed: %w",hopIndex+1,err)}
			out.ToolCalls++
			out.Observations=append(out.Observations,Observation{
				Tool:"walk_relations",CallID:fmt.Sprintf("planned-hop-%d-%d",hopIndex+1,out.ToolCalls),Result:string(walkRaw),
			})
			var walk WalkResult
			if err:=json.Unmarshal(walkRaw,&walk);err!=nil{return out,err}
			if walk.Truncated {out.Incomplete=true}
			byID:=map[string]Asset{}
			for _,node:=range walk.Nodes {byID[node.ID]=node}
			for _,edge:=range walk.Edges {
				if edge.Label!=step.Label || edge.Type!=step.RelationType {continue}
				var destID string
				if step.Direction=="out" && edge.FromID==startID {destID=edge.ToID}
				if step.Direction=="in" && edge.ToID==startID {destID=edge.FromID}
				if destID=="" {continue}
				dest,ok:=byID[destID]
				if !ok || dest.Type!=step.DestinationType {
					out.Incomplete=true
					return out,fmt.Errorf("hop %d returned inconsistent OAM asset or relation type",hopIndex+1)
				}
				if !edgesSeen[edge.ID] && len(edgesSeen)>=a.Runner.Limits.MaxEdges ||
					!nodesSeen[dest.ID] && len(nodesSeen)>=a.Runner.Limits.MaxNodes ||
					len(next)>=a.Runner.Limits.MaxNodes {
					out.Incomplete=true
					break
				}
				edgesSeen[edge.ID]=true
				nodesSeen[dest.ID]=true
				np:=partialPath{
					nodes:append(append([]Asset{},path.nodes...),dest),
					edges:append(append([]Relation{},path.edges...),edge),
				}
				next=append(next,np)
			}
		}
		paths=next
		if len(paths)==0 {break}
	}
	out.Matches=make([]PlanMatch,0,len(paths))
	for _,path:=range paths {out.Matches=append(out.Matches,PlanMatch{Nodes:path.nodes,Edges:path.edges})}
	sort.Slice(out.Matches,func(i,j int)bool{return formatMatch(out.Matches[i])<formatMatch(out.Matches[j])})
	if len(out.Matches)==0 {
		out.Answer=fmt.Sprintf("No matching %d-hop OAM relationship paths were returned for %q by this database; this does not prove the relationships do not exist.",len(plan.Hops),plan.Subject.Name)
	} else {
		segments:=make([]string,0,len(out.Matches))
		for _,match:=range out.Matches {segments=append(segments,formatMatch(match))}
		out.Answer=fmt.Sprintf("Found %d matching OAM path(s): %s. Results reflect stored graph relationships, not independent ownership verification.",len(segments),strings.Join(segments,"; "))
	}
	if out.Incomplete {out.Answer+=" The traversal was truncated; results may be incomplete."}
	return out,nil
}

func formatMatch(p PlanMatch) string {
	parts:=[]string{humanAsset(p.Nodes[0])}
	for i,e:=range p.Edges {
		parts=append(parts,fmt.Sprintf("--%s [edge %s]--> %s",e.Label,e.ID,humanAsset(p.Nodes[i+1])))
	}
	return strings.Join(parts," ")
}
func humanAsset(a Asset)string {
	display:=a.Key
	// Content is an OAM struct in database adapters and a map after JSON
	// decoding. Pull display fields only from JSON to avoid model speculation.
	data,err:=json.Marshal(a.Content)
	if err==nil {
		var fields map[string]json.RawMessage
		if json.Unmarshal(data,&fields)==nil {
			for _,key:=range []string{"name","url"} {
				var value string
				if json.Unmarshal(fields[key],&value)==nil && value!="" {display=value;break}
			}
		}
	}
	return fmt.Sprintf("%s (asset %s)",display,a.ID)
}
