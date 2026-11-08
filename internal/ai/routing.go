// SPDX-License-Identifier: Apache-2.0
package ai

import (
 "context"
 "errors"
 "fmt"
 "sort"

 "github.com/owasp-amass/amass/v5/internal/ai/classify"
)

const OrganizationFeatureVersion = "oam-provenance-v1"
const OrganizationClassificationTask = "organization_relation"

// Source identities describe recorded provenance, not proven independence.
type EvidenceSummary struct {
 EvidenceIDs []string `json:"evidence_ids"`
 SourceIDs []string `json:"source_ids"`
 SourceProperties int `json:"source_properties"`
 Unattributed int `json:"unattributed"`
}

// ExtractProvenanceFeatures must receive evidence IDs checked against the OAM
// database by its caller. It deliberately does not interpret untrusted text.
func ExtractProvenanceFeatures(c Candidate) (classify.Input, EvidenceSummary, error) {
 var out EvidenceSummary
 if c.SubjectID == "" || c.ObjectID == "" || c.SubjectID == c.ObjectID {
  return classify.Input{},out,errors.New("invalid candidate endpoints")
 }
 if len(c.AllowedLabels)==0 || len(c.Evidence)>100 {
  return classify.Input{},out,errors.New("invalid taxonomy or evidence count")
 }
 seen:=map[string]string{}
 sources:=map[string]bool{}
 for _,ev:=range c.Evidence {
  if ev.ID=="" {return classify.Input{},out,errors.New("evidence without ID")}
  if previous,ok:=seen[ev.ID];ok {
   if previous!=ev.SourceID {return classify.Input{},out,fmt.Errorf("conflicting provenance for evidence %q",ev.ID)}
   continue
  }
  seen[ev.ID]=ev.SourceID
  if ev.SourceID=="" {out.Unattributed++} else {sources[ev.SourceID]=true}
  if ev.Kind=="SourceProperty" && ev.SourceID!="" {out.SourceProperties++}
 }
 for id:=range seen {out.EvidenceIDs=append(out.EvidenceIDs,id)}
 for id:=range sources {out.SourceIDs=append(out.SourceIDs,id)}
 sort.Strings(out.EvidenceIDs);sort.Strings(out.SourceIDs)
 n:=len(seen)
 fraction:=func(a,b int)float64{if b==0{return 0};return float64(a)/float64(b)}
 input:=classify.Input{Task:OrganizationClassificationTask,Features:map[string]float64{
  "distinct_sources":minNumber(float64(len(sources))/3,1),
  "evidence_count":minNumber(float64(n)/8,1),
  "source_property_fraction":fraction(out.SourceProperties,n),
  "unattributed_fraction":fraction(out.Unattributed,n),
 }}
 return input,out,nil
}
func minNumber(a,b float64)float64{if a<b{return a};return b}

// Default policy never skips candidates based on uncalibrated predictions.
type RoutingPolicy struct {
 AllowLocalReview bool
 AllowCalibratedSkip bool
}
type RoutingResult struct {
 Decision string `json:"decision"`
 Reason string `json:"reason"`
 Prediction *classify.Prediction `json:"prediction,omitempty"`
 Provenance EvidenceSummary `json:"provenance"`
 Proposal *Proposal `json:"proposal,omitempty"`
 UsedGenerativeModel bool `json:"used_generative_model"`
}

// AnalyzeRouted is read-only: local review results are triage-only, and the
// existing Inferrer.Analyze generates separately validated proposals.
func (i Inferrer) AnalyzeRouted(ctx context.Context,c Candidate,model classify.Classifier,policy RoutingPolicy)(RoutingResult,error){
 var result RoutingResult
 if err:=ctx.Err();err!=nil{return result,err}
 if i.MinSources<2{return result,errors.New("minimum distinct sources must be >= 2")}
 input,provenance,err:=ExtractProvenanceFeatures(c)
 if err!=nil{return result,err}
 result.Provenance=provenance
 if len(provenance.SourceIDs)<i.MinSources{
  result.Decision="needs_evidence"
  result.Reason="insufficient attributed sources; no model request made"
  return result,nil
 }
 if model!=nil{
  prediction,err:=model.Classify(ctx,input)
  if err!=nil{return result,fmt.Errorf("classifier: %w",err)}
  if prediction.FeatureVersion!=OrganizationFeatureVersion {
   return result,fmt.Errorf("classifier feature version %q does not match %q",prediction.FeatureVersion,OrganizationFeatureVersion)
  }
  result.Prediction=&prediction
  if prediction.Decision=="review" && policy.AllowLocalReview {
   result.Decision="review"
   result.Reason="human review required; no OAM relationship proposed or accepted"
   return result,nil
  }
  if prediction.Decision=="skip" && prediction.ScoreKind=="calibrated_probability" && policy.AllowCalibratedSkip {
   result.Decision="skip"
   result.Reason="explicit calibrated triage policy; not proof of non-ownership"
   return result,nil
  }
 }
 if i.Model==nil {
  result.Decision="escalate"
  result.Reason="generative model required"
  return result,nil
 }
 result.UsedGenerativeModel=true
 proposal,err:=i.Analyze(ctx,c)
 if err!=nil{return result,err}
 if proposal==nil {
  result.Decision="no_proposal"
  result.Reason="generative model returned no supported relation"
  return result,nil
 }
 result.Decision="proposed"
 result.Reason="proposal requires review and is not a trusted OAM edge"
 result.Proposal=proposal
 return result,nil
}
