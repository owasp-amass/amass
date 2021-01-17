-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local url = require("url")

name = "Yahoo"
type = "scrape"

function start()
    setratelimit(1)
end

function vertical(ctx, domain)
    for i=0,10 do
        local ok = scrape(ctx, {['url']=buildurl(domain, i)})
        if not ok then
            break
        end

        checkratelimit()
    end
end

function buildurl(domain, pagenum)
    local next = tostring((pagenum * 10) + 1)
    local query = "site:" .. domain .. " -domain:www." .. domain
    local params = {
        p=query,
		b=next,
        pz="10",
        bct="0",
        xargs="0",
    }

    return "https://search.yahoo.com/search?" .. url.build_query_string(params)
end
