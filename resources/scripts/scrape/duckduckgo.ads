-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "DuckDuckGo"
type = "scrape"

function start()
    set_rate_limit(2)
end

function vertical(ctx, domain)
    local vurl = "https://html.duckduckgo.com/html/?q=site:" .. domain .. " -site:www." .. domain

    scrape(ctx, {['url']=vurl})
end
