-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local url = require("url")
local json = require("json")

name = "Maltiverse"
type = "api"

function start()
    set_rate_limit(1)
end

function vertical(ctx, domain)
    local p = 0

    while(true) do
        local resp, err = request(ctx, {['url']=build_url(domain, p)})
        if (err ~= nil and err ~= "") then
            log(ctx, "vertical request to service failed: " .. err)
            return
        elseif (resp.status_code < 200 or resp.status_code >= 400) then
            log(ctx, "vertical request to service returned with status: " .. resp.status)
            return
        end

        local d = json.decode(resp.body)
        if (d == nil) then
            log(ctx, "failed to decode the JSON response")
            return
        elseif (d.hits == nil or #(d['hits'].hits) == 0) then
            return
        end

        for _, h in pairs(d['hits'].hits) do
            if (h['_source'].hostname ~= nil and h['_source'].hostname ~= "") then
                new_name(ctx, h['_source'].hostname)
            end
            if (h['_source'].resolved_ip ~= nil) then
                for _, i in pairs(h['_source'].resolved_ip) do
                    new_addr(ctx, i.ip_addr, h['_source'].hostname)
                end
            end
        end

        if (#(d['hits'].hits) < 500) then
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
