-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local url = require("url")

name = "Ask"
type = "scrape"

function start()
    setratelimit(1)
end

function vertical(ctx, domain)
    for i=1,10 do
        local ok = scrape(ctx, {['url']=buildurl(domain, i)})
        if not ok then
            break
        end

        checkratelimit()
    end
end

function buildurl(domain, pagenum)
    local params = {
        q="site:" .. domain .. " -www." .. domain,
        o="0",
        l="dir",
        qo="pagination",
        page=pagenum,
    }

    return "https://www.ask.com/web?" .. url.build_query_string(params)
end
