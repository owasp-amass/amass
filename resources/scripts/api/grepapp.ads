-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local url = require("url")

name = "GrepApp"
type = "api"

function start()
    set_rate_limit(1)
end

function vertical(ctx, domain)
    for i=1,20 do
        local ok = scrape(ctx, {url=api_url(domain, i)})
        if not ok then
            return
        end

        check_rate_limit()
    end
end

function api_url(domain, pagenum)
    local regex = "[.a-zA-Z0-9-]*[.]" .. domain:gsub("%.", "[.]")
    local params = {
        ['q']=regex,
        ['format']="e",
        ['page']=pagenum,
        ['regexp']='true',
    }

    return "https://grep.app/api/search?" .. url.build_query_string(params)
end
