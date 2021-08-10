-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local url = require("url")

name = "GrepApp"
type = "api"

function start()
    set_rate_limit(2)
end

function vertical(ctx, domain)
    for i=1,20 do
        local page, err = request(ctx, {url=api_url(domain, i)})
        if (err ~= nil and err ~= "") then
            break
        end

        page = page:gsub("<mark>", "")
        local ok = find_names(ctx, page)
        if not ok then
            break
        end

        check_rate_limit()
    end
end

function api_url(domain, pagenum)
    local params = {
        ['q']="." .. domain,
        ['format']="e",
        ['page']=pagenum,
    }

    return "https://grep.app/api/search?" .. url.build_query_string(params)
end

function find_names(ctx, content)
    local names = find(content, subdomain_regex)
    if (names == nil or #names == 0) then
        return false
    end

    for i, name in pairs(names) do
        new_name(ctx, name)
    end
    return true
end
