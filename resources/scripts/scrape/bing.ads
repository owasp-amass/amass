-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local url = require("url")

name = "Bing"
type = "scrape"

function start()
    setratelimit(1)
end

function vertical(ctx, domain)
    for i=1,201,10 do
        local ok = scrape(ctx, {['url']=buildurl(domain, i)})
        if not ok then
            break
        end

        checkratelimit()
    end
end

function buildurl(domain, pagenum)
    local query = "domain:" .. domain .. " -site:www." .. domain
    local params = {
        q=query,
        first=pagenum,
        FORM="PORE",
    }

    return "https://www.bing.com/search?" .. url.build_query_string(params)
end
