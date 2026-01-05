module github.com/owasp-amass/amass/v5

go 1.25

require (
	github.com/InfluxCommunity/influxdb3-go/v2 v2.11.0
	github.com/PuerkitoBio/goquery v1.11.0
	github.com/PuerkitoBio/purell v1.2.1
	github.com/adrg/strutil v0.3.1
	github.com/caffix/fullname_parser v0.0.0-20251125232100-56f069a7ca05
	github.com/caffix/jarm-go v0.0.0-20240920030848-1c7ab2423494
	github.com/caffix/pipeline v0.3.0
	github.com/caffix/queue v0.4.0
	github.com/caffix/stringset v0.2.1-0.20251119025138-9044e6b53d5b
	github.com/cheggaaa/pb/v3 v3.1.7
	github.com/fatih/color v1.18.0
	github.com/geziyor/geziyor v0.0.0-20240812061556-229b8ca83ac1
	github.com/glebarez/sqlite v1.11.0
	github.com/go-ini/ini v1.67.0
	github.com/google/uuid v1.6.0
	github.com/gorilla/mux v1.8.1
	github.com/gorilla/websocket v1.5.3
	github.com/hashicorp/go-multierror v1.1.1
	github.com/likexian/whois v1.15.7
	github.com/likexian/whois-parser v1.24.21
	github.com/miekg/dns v1.1.69
	github.com/nyaruka/phonenumbers v1.6.7
	github.com/openrdap/rdap v0.9.1
	github.com/owasp-amass/asset-db v0.23.2-0.20251230000050-356706aa9b01
	github.com/owasp-amass/open-asset-model v0.15.0
	github.com/owasp-amass/resolve v0.9.7-0.20251129211322-c54b3063b5ae
	github.com/samber/slog-common v0.19.0
	github.com/samber/slog-syslog/v2 v2.5.2
	github.com/stretchr/testify v1.11.1
	github.com/tylertreat/BoomFilters v0.0.0-20251117164519-53813c36cc1b
	github.com/yl2chen/cidranger v1.0.2
	golang.org/x/net v0.48.0
	golang.org/x/time v0.14.0
	gopkg.in/yaml.v3 v3.0.1
	gorm.io/gorm v1.31.1
	mvdan.cc/xurls/v2 v2.6.0
)

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/VividCortex/ewma v1.2.0 // indirect
	github.com/VividCortex/gohistogram v1.0.0 // indirect
	github.com/alecthomas/kingpin/v2 v2.4.0 // indirect
	github.com/alecthomas/units v0.0.0-20240927000941-0f3dac36c52b // indirect
	github.com/andybalholm/cascadia v1.3.3 // indirect
	github.com/apache/arrow-go/v18 v18.5.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/chromedp/cdproto v0.0.0-20250803210736-d308e07a266d // indirect
	github.com/chromedp/chromedp v0.14.2 // indirect
	github.com/chromedp/sysutil v1.1.0 // indirect
	github.com/clipperhouse/stringish v0.1.1 // indirect
	github.com/clipperhouse/uax29/v2 v2.3.0 // indirect
	github.com/d4l3k/messagediff v1.2.1 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/glebarez/go-sqlite v1.22.0 // indirect
	github.com/go-gorp/gorp/v3 v3.1.0 // indirect
	github.com/go-json-experiment/json v0.0.0-20251027170946-4849db3c2f7e // indirect
	github.com/go-kit/kit v0.13.0 // indirect
	github.com/gobwas/httphead v0.1.0 // indirect
	github.com/gobwas/pool v0.2.1 // indirect
	github.com/gobwas/ws v1.4.0 // indirect
	github.com/goccy/go-json v0.10.5 // indirect
	github.com/google/flatbuffers v25.12.19+incompatible // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/influxdata/line-protocol/v2 v2.2.1 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/pgx/v5 v5.8.0 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/klauspost/compress v1.18.2 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/likexian/gokit v0.25.16 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.19 // indirect
	github.com/mattn/go-sqlite3 v1.14.33 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/neo4j/neo4j-go-driver/v5 v5.28.4 // indirect
	github.com/pierrec/lz4/v4 v4.1.23 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/prometheus/client_golang v1.23.2 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.67.5 // indirect
	github.com/prometheus/procfs v0.19.2 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/rubenv/sql-migrate v1.8.1 // indirect
	github.com/samber/lo v1.52.0 // indirect
	github.com/temoto/robotstxt v1.1.2 // indirect
	github.com/xhit/go-str2duration/v2 v2.1.0 // indirect
	github.com/zeebo/xxh3 v1.0.2 // indirect
	go.yaml.in/yaml/v2 v2.4.3 // indirect
	golang.org/x/crypto v0.46.0 // indirect
	golang.org/x/exp v0.0.0-20251219203646-944ab1f22d93 // indirect
	golang.org/x/mod v0.31.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	golang.org/x/telemetry v0.0.0-20251222180846-3f2a21fb04ff // indirect
	golang.org/x/text v0.32.0 // indirect
	golang.org/x/tools v0.40.0 // indirect
	golang.org/x/xerrors v0.0.0-20240903120638-7835f813f4da // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251222181119-0a764e51fe1b // indirect
	google.golang.org/grpc v1.78.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	modernc.org/libc v1.67.4 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
	modernc.org/sqlite v1.42.2 // indirect
)
