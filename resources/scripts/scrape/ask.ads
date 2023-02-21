-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local url = require("url")

name = "Ask"
type = "scrape"

function start()
    set_rate_limit(1)
end

function vertical(ctx, domain)
    for i=1,10 do
        local ok = scrape(ctx, {['url']=build_url(domain, i)})
        if not ok then
            break
        end
    end
end

function build_url(domain, pagenum)
    local params = {
        ['q']="site:" .. domain .. " -www." .. domain,
        ['o']="0",
        ['l']="dir",
        ['qo']="pagination",
        ['page']=pagenum,
    }

    return "https://www.ask.com/web?" .. url.build_query_string(params)
end
