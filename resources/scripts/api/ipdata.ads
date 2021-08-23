-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "IPdata"
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

function asn(ctx, addr, asn)
    if addr == "" then
        return
    end

    local c
    local cfg = datasrc_config()
    if cfg ~= nil then
        c = cfg.credentials
    end

    if (c == nil or c.key == nil or c.key == "") then
        return
    end

    local resp, err = request(ctx, {url=build_url(addr, c.key)})
    if (err ~= nil and err ~= "") then
        return
    end

    local d = json.decode(resp)
    if (d == nil or d.asn == nil) then
        return
    end

    new_asn(ctx, {
        addr=addr,
        asn=tonumber(d.asn:gsub(3)),
        desc=d.name,
        prefix=d.route,
        netblocks={d.route},
    })
end

function build_url(addr, key)
    return "https://api.ipdata.co/" .. addr .. "/asn?api-key=" .. key
end
