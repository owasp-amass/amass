// SPDX-License-Identifier: Apache-2.0
package classify
import("context";"math";"strings";"testing")
const fixture=`{"model_id":"synthetic-linear-v1","task":"organization_relation","feature_version":"v1","skip_threshold":0.97,"review_threshold":0.97,"classes":[{"label":"unrelated","bias":0,"weights":{"verified_negative":8,"legal_record_match":-8}},{"label":"potential_relation","bias":0,"weights":{"verified_negative":-8,"legal_record_match":8}}]}`
func TestLinearModelRoutes(t *testing.T){
 m,err:=Load(strings.NewReader(fixture));if err!=nil{t.Fatal(err)}
 cases:=[]struct{features map[string]float64;want string}{
 {map[string]float64{"verified_negative":1},"skip"},
 {map[string]float64{"legal_record_match":1},"review"},
 {map[string]float64{"verified_negative":.5,"legal_record_match":.5},"escalate"},
 }
 for _,tc:=range cases{
  got,err:=m.Classify(context.Background(),Input{Task:"organization_relation",Features:tc.features})
  if err!=nil||got.Decision!=tc.want{t.Fatalf("%v: got %+v err %v",tc,got,err)}
  if got.ScoreKind!="uncalibrated_softmax"{t.Fatal("uncalibrated score not labeled")}
 }
}
func TestLinearRejectsInvalidFeatures(t *testing.T){
 m,_:=Load(strings.NewReader(fixture))
 for _,features:=range []map[string]float64{{"unknown_feature":1},{"verified_negative":math.NaN()},{"verified_negative":1.5}}{
  if _,err:=m.Classify(context.Background(),Input{Task:m.Task,Features:features});err==nil{t.Fatal("accepted invalid feature")}
 }
}
func TestLinearRejectsMalformedModel(t *testing.T){
 for _,raw:=range []string{`{}`,fixture+"{}",strings.Replace(fixture,`"model_id"`,`"surprise"`,1)}{
  if _,err:=Load(strings.NewReader(raw));err==nil{t.Fatal("accepted malformed model")}
 }
}
func TestLinearContext(t *testing.T){
 m,_:=Load(strings.NewReader(fixture))
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 if _,err:=m.Classify(ctx,Input{Task:m.Task,Features:map[string]float64{"verified_negative":1}});err==nil{t.Fatal("cancellation ignored")}
}
