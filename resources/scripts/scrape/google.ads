-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local url = require("url")

name = "Google"
type = "scrape"

function start()
    set_rate_limit(5)
end

function vertical(ctx, domain)
    for d=1,2 do
        for i=0,20,10 do
            local ok = scrape(ctx, {['url']=build_url(domain, d, i)})
            if not ok then
                log(ctx, "access to search engine is blocked")
                return
            end
        end
    end
end

function build_url(domain, depth, start)
    local query = "site:" .. string.rep("*.", depth) .. domain .. " -www.*"
    local params = {
        ['q']=query,
        ['start']=start,
        ['btnG']="Search",
        ['hl']="en",
        ['biw']="",
        ['bih']="",
        ['gbv']="1",
        ['filter']="0",
    }

    return "https://www.google.com/search?" .. url.build_query_string(params)
end
