module github.com/OWASP/Amass/v3

go 1.16

require (
	github.com/AndreasBriese/bbloom v0.0.0-20190825152654-46b345b51c96
	github.com/PuerkitoBio/goquery v1.6.0
	github.com/caffix/eventbus v0.0.0-20210301213705-9ab42753d12d
	github.com/caffix/pipeline v0.0.0-20210301171240-503915daec5b
	github.com/caffix/queue v0.0.0-20210301212750-6e488abe1004
	github.com/caffix/service v0.0.0-20210202222504-bfa33e78ab27
	github.com/caffix/stringset v0.0.0-20201218054545-37e95a70826c
	github.com/cayleygraph/cayley v0.7.7
	github.com/cayleygraph/quad v1.2.4
	github.com/cjoudrey/gluaurl v0.0.0-20161028222611-31cbb9bef199
	github.com/cloudflare/cloudflare-go v0.13.6
	github.com/dghubble/go-twitter v0.0.0-20201011215211-4b180d0cc78d
	github.com/fatih/color v1.10.0
	github.com/geziyor/geziyor v0.0.0-20191212210344-cfb16fe1ee0e
	github.com/go-ini/ini v1.62.0
	github.com/google/go-cmp v0.5.4 // indirect
	github.com/google/uuid v1.1.3
	github.com/lib/pq v1.9.0 // indirect
	github.com/miekg/dns v1.1.35
	github.com/rakyll/statik v0.1.7
	github.com/rogpeppe/go-internal v1.6.2 // indirect
	github.com/sirupsen/logrus v1.7.0 // indirect
	github.com/spf13/cobra v1.1.3 // indirect
	github.com/stretchr/testify v1.7.0 // indirect
	github.com/yl2chen/cidranger v1.0.2
	github.com/yuin/gopher-lua v0.0.0-20200816102855-ee81675732da
	go.uber.org/ratelimit v0.1.0
	golang.org/x/net v0.0.0-20201224014010-6772e930b67b
	golang.org/x/oauth2 v0.0.0-20201208152858-08078c50e5b5
	golang.org/x/sync v0.0.0-20201207232520-09787c993a3a // indirect
	golang.org/x/text v0.3.4 // indirect
	golang.org/x/tools v0.1.0 // indirect
	gopkg.in/ini.v1 v1.62.0 // indirect
	layeh.com/gopher-json v0.0.0-20201124131017-552bb3c4c3bf
)

replace github.com/knq/sysutil v1.0.0 => github.com/chromedp/sysutil v1.0.0
