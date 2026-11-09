// SPDX-License-Identifier: Apache-2.0
package classify

import (
 "bufio"
 "crypto/sha256"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "math"
 "sort"
 "strings"
)

// LabeledExample is curated supervised training data. group_id prevents
// the same organization/case appearing in both training and holdout.
type LabeledExample struct {
 GroupID string `json:"group_id"`
 Label string `json:"label"`
 Features map[string]float64 `json:"features"`
}
type TrainingMetrics struct {
 TrainingExamples int `json:"training_examples"`
 HoldoutExamples int `json:"holdout_examples"`
 HoldoutAccuracy float64 `json:"holdout_accuracy"`
 HoldoutPotentialPrecision float64 `json:"holdout_potential_precision"`
 HoldoutPotentialRecall float64 `json:"holdout_potential_recall"`
 ModelID string `json:"model_id"`
 ScoreKind string `json:"score_kind"`
}
var TrainingFeatureNames=[]string{"distinct_sources","evidence_count","source_property_fraction","unattributed_fraction"}

// ReadLabeledJSONL bounds input and validates exact OAM provenance features.
// Observations must be independently labeled before use; these values do not
// prove legal ownership and are not a substitute for quality ground truth.
func ReadLabeledJSONL(r io.Reader)([]LabeledExample,error){
 scanner:=bufio.NewScanner(io.LimitReader(r,8<<20))
 scanner.Buffer(make([]byte,4096),64<<10)
 var out []LabeledExample
 for scanner.Scan(){
  line:=strings.TrimSpace(scanner.Text())
  if line==""{continue}
  if len(out)>=100000{return nil,errors.New("training dataset too large")}
  dec:=json.NewDecoder(strings.NewReader(line));dec.DisallowUnknownFields()
  var example LabeledExample
  if err:=dec.Decode(&example);err!=nil{return nil,fmt.Errorf("training row %d: %w",len(out)+1,err)}
  var extra any
  if err:=dec.Decode(&extra);err!=io.EOF{return nil,fmt.Errorf("training row %d contains trailing data",len(out)+1)}
  if example.GroupID==""||len(example.GroupID)>256 {return nil,errors.New("training group_id required and limited to 256 characters")}
  if example.Label!="unrelated"&&example.Label!="potential_relation"{return nil,fmt.Errorf("unknown label %q",example.Label)}
  if len(example.Features)!=len(TrainingFeatureNames){return nil,errors.New("training rows must provide exactly four provenance features")}
  for _,name:=range TrainingFeatureNames{
   value,exists:=example.Features[name]
   if !exists||math.IsNaN(value)||math.IsInf(value,0)||value<0||value>1{
    return nil,fmt.Errorf("invalid or missing feature %s",name)
   }
  }
  out=append(out,example)
 }
 if err:=scanner.Err();err!=nil{return nil,err}
 return out,nil
}

// TrainLinearModel implements a small, reproducible L2-regularized logistic
// classifier. A group-held-out split prevents case leakage. The output is
// explicitly UNCALIBRATED and cannot authorize negative skips or OAM writes.
func TrainLinearModel(rows []LabeledExample,modelID string)(*LinearModel,TrainingMetrics,error){
 var metrics TrainingMetrics
 if modelID==""||len(modelID)>80{return nil,metrics,errors.New("model_id required (max 80 characters)")}
 if len(rows)<40{return nil,metrics,errors.New("need at least 40 independently labeled examples")}
 training:=make([]LabeledExample,0)
 holdout:=make([]LabeledExample,0)
 counts:=map[string]int{}
 holdoutCounts:=map[string]int{}
 groups:=map[string]string{}
 for _,r:=range rows{
  if prior,ok:=groups[r.GroupID];ok&&prior!=r.Label{
   return nil,metrics,fmt.Errorf("conflicting labels for group %s",r.GroupID)
  }
  groups[r.GroupID]=r.Label
  sum:=sha256.Sum256([]byte(r.GroupID))
  if int(sum[0])%5==0{holdout=append(holdout,r);holdoutCounts[r.Label]++}else{training=append(training,r);counts[r.Label]++}
 }
 if len(groups)<20||len(holdout)<8||counts["unrelated"]<10||counts["potential_relation"]<10||
  holdoutCounts["unrelated"]<2||holdoutCounts["potential_relation"]<2{
  return nil,metrics,errors.New("need 20 independent groups, 8 holdout examples, 10 training examples and 2 holdout examples of each class")
 }
 sort.Slice(training,func(i,j int)bool{
  if training[i].GroupID==training[j].GroupID{return training[i].Label<training[j].Label}
  return training[i].GroupID<training[j].GroupID
 })
 const learningRate=.28
 const regularization=.015
 const iterations=1500
 var weights [4]float64
 bias:=0.0
 for iter:=0;iter<iterations;iter++{
  var grad [4]float64
  var gradBias float64
  for _,sample:=range training{
   score:=bias
   for i,name:=range TrainingFeatureNames{score+=weights[i]*sample.Features[name]}
   probability:=1/(1+math.Exp(-math.Max(-40,math.Min(40,score))))
   label:=0.0
   if sample.Label=="potential_relation"{label=1}
   difference:=probability-label
   gradBias+=difference
   for i,name:=range TrainingFeatureNames{grad[i]+=difference*sample.Features[name]}
  }
  scale:=float64(len(training))
  bias-=learningRate*gradBias/scale
  for i:=range weights{weights[i]-=learningRate*(grad[i]/scale+regularization*weights[i])}
 }
 positiveWeights:=map[string]float64{}
 negativeWeights:=map[string]float64{}
 for i,name:=range TrainingFeatureNames{
  positiveWeights[name]=weights[i]/2
  negativeWeights[name]=-weights[i]/2
 }
 model:=&LinearModel{
  ModelID:modelID,
  Task:"organization_relation",
  FeatureVersion:"oam-provenance-v1",
  Classes:[]LinearClass{
   {Label:"unrelated",Bias:-bias/2,Weights:negativeWeights},
   {Label:"potential_relation",Bias:bias/2,Weights:positiveWeights},
  },
  SkipThreshold:.98,ReviewThreshold:.98,
 }
 if err:=model.Validate();err!=nil{return nil,metrics,err}
 correct,tp,fp,fn:=0,0,0,0
 for _,sample:=range holdout{
  probability,err:=model.ClassifyUnrestricted(sample.Features)
  if err!=nil{return nil,metrics,err}
  predicted:="unrelated"
  if probability>=.5{predicted="potential_relation"}
  if predicted==sample.Label{correct++}
  if predicted=="potential_relation"&&sample.Label=="potential_relation"{tp++}
  if predicted=="potential_relation"&&sample.Label=="unrelated"{fp++}
  if predicted=="unrelated"&&sample.Label=="potential_relation"{fn++}
 }
 metrics=TrainingMetrics{TrainingExamples:len(training),HoldoutExamples:len(holdout),
  HoldoutAccuracy:float64(correct)/float64(len(holdout)),
  HoldoutPotentialPrecision:ratio(tp,tp+fp),HoldoutPotentialRecall:ratio(tp,tp+fn),
  ModelID:modelID,ScoreKind:"uncalibrated_softmax",
 }
 return model,metrics,nil
}
func ratio(a,b int)float64{if b==0{return 0};return float64(a)/float64(b)}
func(m *LinearModel)ClassifyUnrestricted(features map[string]float64)(float64,error){
 if err:=m.Validate();err!=nil{return 0,err}
 scores:=make([]float64,2)
 for i,c:=range m.Classes{
  scores[i]=c.Bias
  for k,v:=range features{scores[i]+=c.Weights[k]*v}
 }
 diff:=scores[1]-scores[0]
 return 1/(1+math.Exp(-math.Max(-40,math.Min(40,diff)))),nil
}
