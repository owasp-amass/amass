// SPDX-License-Identifier: Apache-2.0
package cli

import "testing"

func TestClassifierServiceEndpointGuard(t *testing.T){
 for _,endpoint:=range []string{
  "http://classifier:8092",
  "http://localhost:8092",
  "http://127.0.0.1:8092",
  "https://classifier.example.invalid",
 }{
  if err:=validateClassifierEndpoint(endpoint);err!=nil{t.Errorf("%s should be allowed: %v",endpoint,err)}
 }
 for _,endpoint:=range []string{
  "http://public.example.invalid:8092",
  "http://user:password@classifier:8092",
  "file:///etc/passwd",
  "",
  "https://classifier:8092/#fragment",
 }{
  if err:=validateClassifierEndpoint(endpoint);err==nil{t.Errorf("%s should be rejected",endpoint)}
 }
}
