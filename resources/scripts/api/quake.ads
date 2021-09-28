-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "Quake"
type = "api"

function start()
    set_rate_limit(1)
end

function check()
    local c
    local cfg = datasrc_config()
    if cfg ~= nil then
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
    if cfg ~= nil then
        c = cfg.credentials
    end

    if (c == nil or c.key == nil or c.key == "") then
        return
    end

    local p = 0
    while(true) do
        local body = json.encode({
            ['query']="domain:*." .. domain,
            ['start']=p,
            ['size']=1000,
        })

        local resp, err = request(ctx, {
            ['url']="https://quake.360.cn/api/v3/search/quake_service",
            method="POST",
            data=body,
            headers={
                ['Content-Type']="application/json",
                ['X-QuakeToken']=c.key,
            }
        })
        if (err ~= nil and err ~= "") then
            log(ctx, "vertical request to service failed: " .. err)
            return
        end

        local j = json.decode(resp)
        if (j == nil or j.code ~= 0 or j['meta'].pagination.total == 0) then
            return
        end

        for _, d in pairs(j.data) do
            new_name(ctx, d['service'].http.host)
        end

        if j['meta'].pagination.total < 1000 then
            break
        end
        p = p + 1000
    end
end
