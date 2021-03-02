-- Copyright 2017-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "BinaryEdge"
type = "api"

function start()
    setratelimit(1)
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

    local hdrs={
        ['X-KEY']=c["key"],
        ['Content-Type']="application/json",
    }

    for i=1,500 do
        local resp, err = request(ctx, {
            url=apiurl(domain, i),
            headers=hdrs,
        })
        if (err ~= nil and err ~= "") then
            return
        end
    
        local d = json.decode(resp)
        if (d == nil or #(d.events) == 0) then
            return
        end
    
        for i, v in pairs(d.events) do
            newname(ctx, v)
        end

        if (d.page > 500 or d.page > (d.total / d.pagesize)) then
            return
        end
    end
end

function apiurl(domain, pagenum)
    return "https://api.binaryedge.io/v2/query/domains/subdomain/" .. domain .. "?page=" .. pagenum
end
