-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "DuckDuckGo"
type = "scrape"

function start()
    setratelimit(1)
end

function vertical(ctx, domain)
    scrape(ctx, {['url']="https://html.duckduckgo.com/html/?q=site:" .. domain})
end
