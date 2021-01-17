-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local url = require("url")

name = "Bing"
type = "scrape"

function start()
    setratelimit(1)
end

function vertical(ctx, domain)
    for i=0,20 do
        local ok = scrape(ctx, {['url']=buildurl(domain, i)})
        if not ok then
            break
        end

        checkratelimit()
    end
end

function buildurl(domain, pagenum)
    local f = tostring((pagenum * 10) + 1)
    local query = "domain:" .. domain
    local params = {
        q=query,
		first=f,
		FORM="PORE",
    }

    return "http://www.bing.com/search?" .. url.build_query_string(params)
end
