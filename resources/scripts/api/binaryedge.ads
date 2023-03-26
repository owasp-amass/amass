-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local json = require("json")

name = "BinaryEdge"
type = "api"

function start()
    set_rate_limit(1)
end

function check()
    local c
    local cfg = datasrc_config()
    if (cfg ~= nil) then
        c = cfg.credentials
    end

    if (c ~= nil and c.key ~= nil and c.key ~= "") then
        return true
    end
    return false
end

function vertical(ctx, domain)
    local c
    local cfg = datasrc_config()
    if (cfg ~= nil) then
        c = cfg.credentials
    end

    for i=1,500 do
        local resp, err = request(ctx, {
            ['url']=api_url(domain, i),
            ['header']={['X-KEY']=c.key},
        })
        if (err ~= nil and err ~= "") then
            log(ctx, "vertical request to service for page " .. tostring(i) .. " failed: " .. err)
            return
        elseif (resp.status_code < 200 or resp.status_code >= 400) then
            log(ctx, "vertical request to service for page " .. tostring(i) .. " returned with status: " .. resp.status)
            return
        end
    
        local d = json.decode(resp.body)
        if (d == nil) then
            log(ctx, "failed to decode the JSON response")
            return
        elseif (d.events == nil or #(d.events) == 0) then
            return
        end
    
        for i, v in pairs(d.events) do
            if (v ~= nil and v ~= "") then
                new_name(ctx, v)
            end
        end

        if (d.page ~= nil and d.total ~= nil and 
            d.pagesize ~= nil and d.pagesize ~= 0) then
            if (d.page > 500 or d.page > (d.total / d.pagesize)) then
                return
            end
        end
    end
end

function api_url(domain, pagenum)
    return "https://api.binaryedge.io/v2/query/domains/subdomain/" .. domain .. "?page=" .. pagenum
end
