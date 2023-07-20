-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local url = require("url")

name = "Bing"
type = "scrape"

function start()
    set_rate_limit(1)
end

function vertical(ctx, domain)
    for i=1,20 do
        local ok = scrape(ctx, {['url']=domain_url(domain, i)})
        if not ok then
            break
        end
    end
end

function domain_url(domain, pagenum)
    local query = "domain:" .. domain .. " -www." .. domain
    local params = {
        ['q']=query,
        ['first']=pagenum,
        ['go']="Submit",
    }

    return "https://www.bing.com/search?" .. url.build_query_string(params)
end

function address(ctx, addr)
    for i=1,20 do
        local ok = scrape(ctx, {['url']=addr_url(addr, i)})
        if not ok then
            break
        end
    end
end

function addr_url(addr, pagenum)
    local query = "ip%3A" .. addr
    local params = {
        ['q']=query,
        ['qs']="n",
        ['FORM']="PERE",
        ['first']=pagenum,
    }

    return "https://www.bing.com/search?" .. url.build_query_string(params)
end
