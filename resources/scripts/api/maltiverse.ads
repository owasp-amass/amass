-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local url = require("url")
local json = require("json")

name = "Maltiverse"
type = "api"

function start()
    set_rate_limit(1)
end

function vertical(ctx, domain)
    p = 0
    while(true) do
        local resp, err = request(ctx, {['url']=build_url(domain, p)})
        if (err ~= nil and err ~= "") then
            log(ctx, "vertical request to service failed: " .. err)
            return
        end

        local d = json.decode(resp)
        if (d == nil or d.hits == nil or
            d['hits'].hits == nil or #(d['hits'].hits) == 0) then
            return
        end

        for _, h in pairs(d['hits'].hits) do
            new_name(ctx, h['_source'].hostname)
            for _, i in pairs(h['_source'].resolved_ip) do
                new_addr(ctx, i.ip_addr, h['_source'].hostname)
            end
        end

        if #(d['hits'].hits) < 500 then
            break
        end
        p = p + 500
    end
end

function build_url(domain, pagenum)
    local query = "hostname.keyword:*." .. domain
    local params = {
        ['query']=query,
        ['from']=pagenum,
        ['size']="500",
        ['format']="json",
        ['sort']="creation_time_desc",
    }

    return "https://api.maltiverse.com/search?" .. url.build_query_string(params)
end
