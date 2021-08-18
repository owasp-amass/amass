-- Copyright 2020-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "PassiveTotal"
type = "api"

function start()
    set_rate_limit(5)
end

function check()
    local c
    local cfg = datasrc_config()
    if cfg ~= nil then
        c = cfg.credentials
    end

    if (c ~= nil and c.key ~= nil and
        c.username ~= nil and c.key ~= "" and c.username ~= "") then
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

    if (c == nil or c.key == nil or c.key == "" or
        c.username == nil or c.username == "") then
        return
    end

    local resp, err = request(ctx, {
        url=build_url(domain),
        id=c.username,
        pass=c.key,
    })
    if (err ~= nil and err ~= "") then
        return
    end

    local d = json.decode(resp)
    if (d == nil or d.success ~= true or #d.subdomains == 0) then
        return
    end

    for _, sub in pairs(d.subdomains) do
        new_name(ctx, sub .. "." .. domain)
    end
end

function build_url(domain)
    return "https://api.passivetotal.org/v2/enrichment/subdomains?query=" .. domain
end
