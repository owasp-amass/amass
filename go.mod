module github.com/OWASP/Amass/v3

go 1.16

require (
	github.com/AndreasBriese/bbloom v0.0.0-20190825152654-46b345b51c96
	github.com/PuerkitoBio/goquery v1.6.0
	github.com/caffix/eventbus v0.0.0-20210301213705-9ab42753d12d
	github.com/caffix/netmap v0.0.0-20210412003155-5aec13909475
	github.com/caffix/pipeline v0.0.0-20210415183235-cd7a519dd0e6
	github.com/caffix/queue v0.0.0-20210301212750-6e488abe1004
	github.com/caffix/resolve v0.0.0-20210410021921-f3697cc77395
	github.com/caffix/service v0.0.0-20210321183606-3819810293b0
	github.com/caffix/stringset v0.0.0-20210320213318-a00bc23f59bc
	github.com/cayleygraph/quad v1.2.4
	github.com/cjoudrey/gluaurl v0.0.0-20161028222611-31cbb9bef199
	github.com/cloudflare/cloudflare-go v0.13.6
	github.com/dghubble/go-twitter v0.0.0-20201011215211-4b180d0cc78d
	github.com/fatih/color v1.10.0
	github.com/geziyor/geziyor v0.0.0-20191212210344-cfb16fe1ee0e
	github.com/go-ini/ini v1.62.0
	github.com/google/uuid v1.1.3
	github.com/miekg/dns v1.1.41
	github.com/rakyll/statik v0.1.7
	github.com/yl2chen/cidranger v1.0.2
	github.com/yuin/gopher-lua v0.0.0-20200816102855-ee81675732da
	golang.org/x/net v0.0.0-20210410081132-afb366fc7cd1
	golang.org/x/oauth2 v0.0.0-20201208152858-08078c50e5b5
	golang.org/x/term v0.0.0-20210406210042-72f3dc4e9b72 // indirect
	gopkg.in/ini.v1 v1.62.0 // indirect
	layeh.com/gopher-json v0.0.0-20201124131017-552bb3c4c3bf
)

replace github.com/knq/sysutil v1.0.0 => github.com/chromedp/sysutil v1.0.0
