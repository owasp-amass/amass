-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local json = require("json")

name = "Quake"
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

    if (c == nil or c.key == nil or c.key == "") then
        return
    end

    local p = 0
    while(true) do
        local body, err = json.encode({
            ['query']="domain:*." .. domain,
            ['start']=p,
            ['size']=1000,
        })
        if (err ~= nil and err ~= "") then
            break
        end

        local resp, err = request(ctx, {
            ['url']="https://quake.360.cn/api/v3/search/quake_service",
            ['method']="POST",
            ['header']={
                ['Content-Type']="application/json",
                ['X-QuakeToken']=c.key,
            },
            ['body']=body,
        })
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
        elseif (d.code == nil or d.code ~= 0) then
            return
        elseif (d.meta == nil or d['meta'].pagination == nil or 
            d['meta']['pagination'].total == nil or d['meta']['pagination'].total == 0) then
            return
        end

        for _, d in pairs(d.data) do
            if (d.service ~= nil and d['service'].http ~= nil and 
                d['service']['http'].host ~= nil and d['service']['http'].host ~= "") then
                new_name(ctx, d['service']['http'].host)
            end
        end

        if (d['meta']['pagination'].total < 1000) then
            break
        end
        p = p + 1000
    end
end
