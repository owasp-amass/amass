// SPDX-License-Identifier: Apache-2.0
package classify
import (
 "context"
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
)
func TestHTTPClassifierUntrainedFallbackIndependentOfProvider(t *testing.T){
 server:=httptest.NewServer(HTTPService{}.Handler())
 defer server.Close()
 response,err:=http.Get(server.URL+"/readyz")
 if err!=nil{t.Fatal(err)}
 var ready map[string]any
 if err:=json.NewDecoder(response.Body).Decode(&ready);err!=nil{t.Fatal(err)}
 _=response.Body.Close()
 if response.StatusCode!=200||ready["trained"]!=false||ready["mode"]!="untrained_fallback"{t.Fatalf("fallback status: %+v",ready)}
 client:=HTTPClient{Endpoint:server.URL}
 p,err:=client.Classify(context.Background(),Input{Task:"organization_relation",Features:map[string]float64{"distinct_sources":.5}})
 if err!=nil{t.Fatal(err)}
 if p.Decision!="escalate"||p.ScoreKind!="not_scored"||p.Score!=0{t.Fatalf("untrained fallback asserted confidence: %+v",p)}
}
func TestHTTPClassifierTrainedRoundTrip(t *testing.T){
 model,err:=Load(strings.NewReader(fixture))
 if err!=nil{t.Fatal(err)}
 server:=httptest.NewServer(HTTPService{Model:model}.Handler())
 defer server.Close()
 pred,err:=(HTTPClient{Endpoint:server.URL}).Classify(context.Background(),Input{Task:"organization_relation",Features:map[string]float64{"legal_record_match":1}})
 if err!=nil{t.Fatal(err)}
 if pred.Decision!="review"||pred.ModelID!="synthetic-linear-v1"{t.Fatalf("trained response: %+v",pred)}
}
