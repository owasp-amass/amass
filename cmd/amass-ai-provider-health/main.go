// SPDX-License-Identifier: Apache-2.0
// Command amass-ai-provider-health verifies that the chosen LLM is
// actually responding. Probes are cached between health checks.
package main

import (
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "net/http"
 "net/url"
 "os"
 "os/signal"
 "strings"
 "sync"
 "syscall"
 "time"

 "github.com/owasp-amass/amass/v5/internal/ai"
)

type state struct{sync.RWMutex;ready bool;lastOK time.Time;lastError string}
func main(){if err:=run();err!=nil{fmt.Fprintln(os.Stderr,"amass-ai-provider-health:",err);os.Exit(1)}}
func run()error{
 provider:=os.Getenv("AMASS_AI_PROVIDER")
 if provider==""{provider="compatible"}
 modelName:=os.Getenv("AMASS_AI_MODEL")
 endpoint:=os.Getenv("AMASS_AI_ENDPOINT")
 if modelName==""||endpoint==""{return errors.New("AMASS_AI_MODEL and AMASS_AI_ENDPOINT must be configured")}
 u,err:=url.Parse(endpoint)
 if err!=nil||u.Hostname()==""||u.User!=nil{return errors.New("invalid model endpoint")}
 if u.Scheme!="https" && !(u.Scheme=="http"&&os.Getenv("AMASS_AI_ALLOW_HTTP")=="true"){
  return errors.New("model HTTP requires explicit AMASS_AI_ALLOW_HTTP=true; otherwise use HTTPS")
 }
 timeout:=4*time.Minute
 if raw:=os.Getenv("AMASS_AI_MODEL_TIMEOUT");raw!=""{
  timeout,err=time.ParseDuration(raw)
  if err!=nil||timeout<5*time.Second||timeout>15*time.Minute{return errors.New("invalid model timeout")}
 }
 apiKey:=os.Getenv("AMASS_AI_API_KEY")
 client:=&http.Client{Timeout:timeout}
 var model ai.Model
 switch provider {
 case "compatible":model=ai.CompatibleModel{Endpoint:endpoint,ModelName:modelName,APIKey:apiKey,Client:client}
 case "anthropic":
  if apiKey==""{return errors.New("Anthropic requires AMASS_AI_API_KEY")}
  model=ai.AnthropicModel{Endpoint:endpoint,ModelName:modelName,APIKey:apiKey,Client:client}
 default:return fmt.Errorf("unsupported inference provider %q",provider)
 }
 var status state
 ctx,stop:=signal.NotifyContext(context.Background(),syscall.SIGTERM,syscall.SIGINT)
 defer stop()
 go func(){
  probe:=func(){
   check,cancel:=context.WithTimeout(ctx,timeout)
   defer cancel()
   response,err:=model.Generate(check,[]ai.Message{
    {Role:"system",Text:"Model connectivity check. Reply briefly with READY."},
    {Role:"user",Text:"READY"},
   },nil)
   if err==nil&&strings.TrimSpace(response.Text)==""&&len(response.Calls)==0{
    err=errors.New("model responded without usable content")
   }
   status.Lock()
   status.ready=err==nil
   if err==nil{status.lastOK=time.Now();status.lastError=""}else{status.lastError=err.Error()}
   status.Unlock()
   if err!=nil{fmt.Fprintln(os.Stderr,"inference probe unsuccessful:",err)}else{fmt.Fprintln(os.Stderr,"inference model responded:",provider,modelName)}
  }
  probe()
  for{
   status.RLock();ready:=status.ready;status.RUnlock()
   interval:=20*time.Second
   if ready{interval=5*time.Minute}
   select{case <-ctx.Done():return;case <-time.After(interval):probe()}
  }
 }()
 mux:=http.NewServeMux()
 mux.HandleFunc("GET /healthz",func(w http.ResponseWriter,r *http.Request){
  send(w,200,map[string]any{"status":"running","component":"inference-provider"})
 })
 mux.HandleFunc("GET /readyz",func(w http.ResponseWriter,r *http.Request){
  status.RLock()
  ready,lastOK,lastErr:=status.ready,status.lastOK,status.lastError
  status.RUnlock()
  fresh:=ready&&!lastOK.IsZero()&&time.Since(lastOK)<7*time.Minute
  state:="not_ready";code:=503
  if fresh{state="ready";code=200}
  // The error remains in container logs and must not expose upstream tokens.
  _=lastErr
  send(w,code,map[string]any{"status":state,"provider":provider,"model":modelName,"last_success":lastOK})
 })
 server:=&http.Server{Addr:"0.0.0.0:8091",Handler:mux,ReadHeaderTimeout:5*time.Second}
 go func(){<-ctx.Done();closeCtx,cancel:=context.WithTimeout(context.Background(),5*time.Second);defer cancel();_ =server.Shutdown(closeCtx)}()
 err=server.ListenAndServe()
 if errors.Is(err,http.ErrServerClosed){return nil}
 return err
}
func send(w http.ResponseWriter,status int,v any){
 w.Header().Set("Content-Type","application/json")
 w.Header().Set("Cache-Control","no-store")
 w.WriteHeader(status)
 _=json.NewEncoder(w).Encode(v)
}
