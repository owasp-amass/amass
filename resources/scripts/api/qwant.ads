-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local url = require("url")

name = "Qwant"
type = "api"

function start()
    setratelimit(1)
end

function vertical(ctx, domain)
    for i=0,40,10 do
        local ok = scrape(ctx, {['url']=buildurl(domain, i)})
        if not ok then
            break
        end

        checkratelimit()
    end
end

function buildurl(domain, pagenum)
    local query = "site:" .. domain .. " -www"
    local params = {
        q=query,
        offset=pagenum,
        count="10",
        locale="en_GB",
    }

    return "https://api.qwant.com/v3/search/web" .. url.build_query_string(params)
end
