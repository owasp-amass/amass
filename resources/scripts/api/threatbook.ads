-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "ThreatBook"
type = "api"

function start()
    setratelimit(5)
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

    local resp, err = request(ctx, {
        url=verturl(domain, key),
        headers={['Content-Type']="application/json"},
    })
    if (err ~= nil and err ~= "") then
        return
    end

    local d = json.decode(resp)
    if (d == nil or d.response_code ~= 0 or #(d.sub_domains.data) == 0) then
        return
    end

    for i, sub in pairs(d.sub_domains.data) do
        newname(ctx, sub)
    end
end

function verturl(domain, key)
    return "https://api.threatbook.cn/v3/domain/sub_domains?apikey=" .. key .. "&resource=" .. domain
end
