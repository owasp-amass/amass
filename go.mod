module github.com/OWASP/Amass/v3

go 1.14

require (
	github.com/AndreasBriese/bbloom v0.0.0-20190825152654-46b345b51c96
	github.com/PuerkitoBio/goquery v1.6.0
	github.com/caffix/eventbus v0.0.0-20201229201025-4c5f3ce94295
	github.com/caffix/pipeline v0.0.0-20210106193115-41730a0744af
	github.com/caffix/queue v0.0.0-20210106184330-1d2e72b64fa0
	github.com/caffix/service v0.0.0-20210101222658-354b1fdf7f24
	github.com/caffix/stringset v0.0.0-20201218054545-37e95a70826c
	github.com/cayleygraph/cayley v0.7.7
	github.com/cayleygraph/quad v1.2.4
	github.com/cjoudrey/gluaurl v0.0.0-20161028222611-31cbb9bef199
	github.com/cloudflare/cloudflare-go v0.13.6
	github.com/dghubble/go-twitter v0.0.0-20201011215211-4b180d0cc78d
	github.com/fatih/color v1.10.0
	github.com/geziyor/geziyor v0.0.0-20191212210344-cfb16fe1ee0e
	github.com/go-ini/ini v1.62.0
	github.com/google/uuid v1.1.3
	github.com/jmoiron/sqlx v1.2.0
	github.com/lib/pq v1.9.0
	github.com/miekg/dns v1.1.35
	github.com/rakyll/statik v0.1.7
	github.com/smartystreets/goconvey v1.6.4 // indirect
	github.com/yl2chen/cidranger v1.0.2
	github.com/yuin/gopher-lua v0.0.0-20200816102855-ee81675732da
	go.uber.org/ratelimit v0.1.0
	golang.org/x/net v0.0.0-20201224014010-6772e930b67b
	golang.org/x/oauth2 v0.0.0-20201208152858-08078c50e5b5
	golang.org/x/sync v0.0.0-20201207232520-09787c993a3a
	gopkg.in/ini.v1 v1.62.0 // indirect
	layeh.com/gopher-json v0.0.0-20201124131017-552bb3c4c3bf
)

replace github.com/knq/sysutil v1.0.0 => github.com/chromedp/sysutil v1.0.0
