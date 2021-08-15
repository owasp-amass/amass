-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "PSBDMP"
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

    local resp, err = request(ctx, {url=search_url(domain)})
    if (err ~= nil and err ~= "") then
        return
    end

    local d = json.decode(resp)
    if (d == nil or d.count == 0) then
        return
    end

    for i, dump in pairs(d.data) do
        scrape(ctx, {url=dump_url(dump.id, c.key)})
    end
end

function search_url(domain)
    return "https://psbdmp.ws/api/v3/search/" .. domain
end

function dump_url(id, key)
    return "https://psbdmp.ws/api/v3/dump/" .. id .. "?key=" .. key
end
