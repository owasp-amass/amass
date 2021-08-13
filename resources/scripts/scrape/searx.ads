-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local url = require("url")

name = "Searx"
type = "scrape"

local urls = {}

function start()
    set_rate_limit(1)
end

function vertical(ctx, domain)
    for i=1,20 do
        local query = "site:" .. domain .. " -www"
        local params = {
            ['q']=query,
            ['pageno']=i,
            ['category_general']="1",
            ['time_range']="None",
            ['language']="en-US",
        }

        local ok = scrape(ctx, {
            ['method']="POST",
            ['data']=url.build_query_string(params),
            ['url']="https://searx.info/search",
            ['headers']={['Content-Type']="application/x-www-form-urlencoded"},
        })
        if not ok then
            break
        end

        check_rate_limit()
    end
end
