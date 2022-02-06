
package datasrcs

import (
        "fmt"   
        "testing"

        "github.com/OWASP/Amass/v3/systems"
        "github.com/OWASP/Amass/v3/config"
         
)

func TestGetAllSources(t *testing.T){

    cfg := config.NewConfig()
    sys, err := systems.NewLocalSystem(cfg)
    if err != nil {
        return
    }
        r := GetAllSources(sys)
        if ( fmt.Sprintf("%v", r)!="[360PassiveDNS ARIN AbuseIPDB Ahrefs AlienVault Alterations AnubisDB ArchiveIt Arquivo Ask AskDNS BGPView Baidu BinaryEdge Bing Brute Forcing BufferOver BuiltWith C99 CIRCL Censys CertSpotter Chaos Cloudflare CommonCrawl Crtsh DNSDB DNSDumpster DNSRepo DNSlytics Detectify Digitorus DuckDuckGo FOFA FacebookCT FullHunt Gists GitHub GitLab GoogleCT Greynoise HAW HackerOne HackerTarget Hunter HyperStat IPdata IPinfo IPv4Info IntelX Maltiverse Mnemonic N45HT NetworksDB ONYPHE PKey PassiveTotal PentestTools Quake RADb RapidDNS Riddler Robtex Searchcode Searx SecurityTrails ShadowServer Shodan SiteDossier SonarSearch Spamhaus SpyOnWeb Spyse Sublist3rAPI TeamCymru ThreatBook ThreatCrowd ThreatMiner Twitter UKWebArchive URLScan Umbrella VirusTotal Wayback WhoisXMLAPI Yahoo ZETAlytics ZoomEye]"){
        t.Errorf("got %q, wanted %q", fmt.Sprintf("%v", r), "[360PassiveDNS ARIN AbuseIPDB Ahrefs AlienVault Alterations AnubisDB ArchiveIt Arquivo Ask AskDNS BGPView Baidu BinaryEdge Bing Brute Forcing BufferOver BuiltWith C99 CIRCL Censys CertSpotter Chaos Cloudflare CommonCrawl Crtsh DNSDB DNSDumpster DNSRepo DNSlytics Detectify Digitorus DuckDuckGo FOFA FacebookCT FullHunt Gists GitHub GitLab GoogleCT Greynoise HAW HackerOne HackerTarget Hunter HyperStat IPdata IPinfo IPv4Info IntelX Maltiverse Mnemonic N45HT NetworksDB ONYPHE PKey PassiveTotal PentestTools Quake RADb RapidDNS Riddler Robtex Searchcode Searx SecurityTrails ShadowServer Shodan SiteDossier SonarSearch Spamhaus SpyOnWeb Spyse Sublist3rAPI TeamCymru ThreatBook ThreatCrowd ThreatMiner Twitter UKWebArchive URLScan Umbrella VirusTotal Wayback WhoisXMLAPI Yahoo ZETAlytics ZoomEye]")
        }
}
