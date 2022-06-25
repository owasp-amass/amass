-- Copyright 2022 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")
local url = require("url")

name = "BigDataCloud"
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
    local c
    local cfg = datasrc_config()
    if cfg ~= nil then
        c = cfg.credentials
    end

    if (c == nil or c.key == nil or c.key == "") then
        return
    end

    local resp, err = request(ctx, {['url']=build_url(addr, c.key)})
    if (err ~= nil and err ~= "") then
        log(ctx, "asn request to service failed: " .. err)
        return
    end

    local j = json.decode(resp)
    if j == nil then
        return
    end

    new_asn(ctx, {
        ['addr']=addr,
        ['asn']=j.carriers[1].asnNumeric,
        ['cc']=j.registeredCountry,
        ['desc']=j.organisation,
        ['registry']=j.registry,
        ['prefix']=j.bgpPrefix,
    })
end

function build_url(addr, key)
    local params = {
        ['localityLanguage']="en",
        ['ip']=addr,
        ['key']=key,
    }

    return "https://api.bigdatacloud.net/data/network-by-ip?" .. url.build_query_string(params)
end
