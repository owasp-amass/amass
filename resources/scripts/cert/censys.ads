-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local json = require("json")

name = "Censys"
type = "cert"

function start()
    set_rate_limit(3)
end

function check()
    local c
    local cfg = datasrc_config()
    if cfg ~= nil then
        c = cfg.credentials
    end

    if (c ~= nil and c.key ~= nil and 
        c.key ~= "" and c.secret ~= nil and c.secret ~= "") then
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

    if (c == nil or c.key == nil or c.key == "" or c.secret == nil or c.secret == "") then
        return
    end

    api_query(ctx, cfg, domain)
end

function api_query(ctx, cfg, domain)
    local p = 1

    while(true) do
        local err, body, status, data
        data, err = json.encode({
            ['query']="parsed.names: " .. domain, 
            ['page']=p,
            ['fields']={"parsed.names"},
        })
        if (err ~= nil and err ~= "") then
            return
        end
    
        _, body, status, err = request(ctx, {
            ['method']="POST",
            ['data']=data,
            ['url']="https://search.censys.io/api/v1/search/certificates",
            ['headers']={['Content-Type']="application/json"},
            ['id']=cfg["credentials"].key,
            ['pass']=cfg["credentials"].secret,
        })
        if ((err ~= nil and err ~= "") or status < 200 or status >= 400) then
            log(ctx, "vertical request to service failed with status code " .. tostring(status) .. ": " .. err)
            return nil
        end

        local d = json.decode(body)
        if (d == nil) then
            log(ctx, "failed to decode the JSON response")
            return
        elseif (d.status == nil or d.status ~= "ok" or #(d.results) == 0) then
            return
        end

        for _, r in pairs(d.results) do
            for _, v in pairs(r["parsed.names"]) do
                new_name(ctx, v)
            end
        end

        if d["metadata"].page >= d["metadata"].pages then
            return
        end
        p = p + 1
    end
end
