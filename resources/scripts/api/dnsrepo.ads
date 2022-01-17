-- Copyright 2022 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "DNSRepo"
type = "api"

function start()
    set_rate_limit(2)
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

    local resp, err = request(ctx, {['url']=build_url(domain, c.key)})
    if (err ~= nil and err ~= "") then
        log(ctx, "vertical request to service failed: " .. err)
        return
    end
    resp = "{\"results\":" .. resp .. "}"

    local d = json.decode(resp)
    if (d == nil or d.results == nil or #(d.results) == 0) then
        return
    end

    for _, r in pairs(d.results) do
        new_name(ctx, r.domain)
    end
end

function build_url(domain, key)
    return "https://dnsrepo.noc.org/api/?apikey=" .. key .. "&search=" .. domain .. "&limit=5000"
end
