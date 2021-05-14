-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local url = require("url")
local json = require("json")

name = "Baidu"
type = "scrape"

function start()
    setratelimit(1)
end

function vertical(ctx, domain)
    for i=1,10 do
        checkratelimit()

        local ok = scrape(ctx, {['url']=buildurl(domain, i)})
        if not ok then
            break
        end
    end
end

function buildurl(domain, pagenum)
    local query = "site:" .. domain .. " -site:www." .. domain
    local params = {
        wd=query,
        oq=query,
        pn=pagenum,
    }

    return "https://www.baidu.com/s?" .. url.build_query_string(params)
end
