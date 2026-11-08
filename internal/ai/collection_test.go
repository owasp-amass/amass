// SPDX-License-Identifier: Apache-2.0
package ai

import (
 "strings"
 "testing"
)

func TestPlanCollectionRequiresExactSupportedSelector(t *testing.T){
 cases:=[]struct{
  selector AssetSelector
  wantType string
  wantValue string
 }{
  {AssetSelector{Type:"FQDN",Field:"name",Value:"WWW.Example.org."},"domain","www.example.org"},
  {AssetSelector{Type:"IPAddress",Field:"address",Value:"8.8.8.8"},"ip","8.8.8.8"},
  {AssetSelector{Type:"Netblock",Field:"cidr",Value:"8.8.8.0/24"},"cidr","8.8.8.0/24"},
  {AssetSelector{Type:"AutonomousSystem",Field:"number",Value:"15169"},"asn","15169"},
 }
 for _,tc:=range cases{
  plan:=PlanCollection(tc.selector)
  if plan.Status!="approval_required" || plan.ID=="" || !plan.RequiresApproval || len(plan.Methods)!=1 || plan.ScopeType!=tc.wantType || plan.ScopeValue!=tc.wantValue {
   t.Errorf("unexpected collection plan for %+v: %+v",tc.selector,plan)
  }
  if second:=PlanCollection(tc.selector);second.ID!=plan.ID {t.Errorf("nondeterministic approval id: %s vs %s",plan.ID,second.ID)}
 }
}
func TestCollectionCannotExpandToUnsupportedOrInvalidTargets(t *testing.T){
 cases:=[]AssetSelector{
  {Type:"Organization",Field:"name",Value:"Acme"},
  {Type:"ContactRecord",Field:"name",Value:"Owner"},
  {Type:"FQDN",Field:"name",Value:"bad..example.org"},
  {Type:"FQDN",Field:"name",Value:"-bad.example.org"},
  {Type:"IPAddress",Field:"address",Value:"127.0.0.1"},
  {Type:"IPAddress",Field:"address",Value:"10.0.0.1"},
  {Type:"Netblock",Field:"cidr",Value:"192.168.0.0/16"},
  {Type:"AutonomousSystem",Field:"number",Value:"0"},
  {Type:"FQDN",EntityID:"123"},
 }
 for _,target:=range cases{
  plan:=PlanCollection(target)
  if plan.Status!="unsupported" || plan.ID!="" || len(plan.Methods)!=0 || strings.TrimSpace(plan.Reason)=="" {t.Errorf("unsafe collection plan: %+v",plan)}
 }
}
func TestCollectionApprovalsBindScopeAndMethod(t *testing.T){
 a:=PlanCollection(AssetSelector{Type:"FQDN",Field:"name",Value:"a.example.org"})
 b:=PlanCollection(AssetSelector{Type:"FQDN",Field:"name",Value:"b.example.org"})
 if a.ID==b.ID {t.Fatal("distinct target scopes share approval id")}
}
