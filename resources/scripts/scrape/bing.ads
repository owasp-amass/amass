-- Copyright 2017-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local url = require("url")

name = "Bing"
type = "scrape"

function start()
    set_rate_limit(1)
end

function vertical(ctx, domain)
    for i=1,201,10 do
        local ok = scrape(ctx, {['url']=build_url(domain, i)})
        if not ok then
            break
        end
    end
end

function build_url(domain, pagenum)
    local query = "domain:" .. domain .. " -site:www." .. domain
    local params = {
        q=query,
        first=pagenum,
        FORM="PORE",
    }

    return "https://www.bing.com/search?" .. url.build_query_string(params)
end
