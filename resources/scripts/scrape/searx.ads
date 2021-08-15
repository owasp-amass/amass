-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local url = require("url")

name = "Searx"
type = "scrape"

function start()
    set_rate_limit(2)
end

function vertical(ctx, domain)
    -- Qualified best Searx instances
    local instances = {
        "https://anon.sx",
        "https://searx.info",
        "https://searx.ru",
        "https://searx.run",
        "https://searx.sk",
        "https://xeek.com",
    }
    -- Randomly choose one instance for scraping
    math.randomseed(os.time())
    local host = instances[math.random(1, 6)] .. "/search"

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
            url=host,
            method="POST",
            data=url.build_query_string(params),
            headers={['Content-Type']="application/x-www-form-urlencoded"},
        })
        if not ok then
            break
        end
    end
end
