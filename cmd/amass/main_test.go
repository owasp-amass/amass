package main

import (
	"testing"
)

func TestGetallSourceNames(t *testing.T) {

	want := []string{"AlienVault", "ArchiveIt", "ArchiveToday", "Arquivo", "Ask", "Baidu",
		"BinaryEdge", "Bing", "BufferOver", "Censys", "CertSpotter", "CIRCL", "CommonCrawl", "Crtsh", "DNSDB", "DNSDumpster",
		"DNSTable", "Dogpile", "Entrust", "Exalead", "GitHub", "Google", "GoogleCT", "HackerOne", "HackerTarget", "IPToASN",
		"IPv4Info", "LoCArchive", "Mnemonic", "Netcraft", "NetworksDB", "OpenUKArchive", "PassiveTotal", "Pastebin", "PTRArchive", "RADb",
		"Riddler", "Robtex", "SiteDossier", "SecurityTrails", "ShadowServer", "Shodan", "Spyse", "Sublist3rAPI", "TeamCymru", "ThreatCrowd", "Twitter",
		"UKGovArchive", "Umbrella", "URLScan", "ViewDNS", "VirusTotal", "Wayback", "WhoisXML", "Yahoo"}
	got := GetAllSourceNames()

	for i, get := range got {
		if want[i] != get {
			t.Errorf("Want:%v\nGet:%v\n", want[i], get)
		}
	}

}
