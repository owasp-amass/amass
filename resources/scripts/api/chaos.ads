-- Copyright 2017-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "Chaos"
type = "api"

function start()
    set_rate_limit(10)
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

    local resp, err = request(ctx, {
        url=build_url(domain),
        headers={['Authorization']=c.key},
    })
    if (err ~= nil and err ~= "") then
        return
    end

    local d = json.decode(resp)
    if (d == nil or d.subdomains == nil or #d.subdomains == 0) then
        return
    end

    for i, sub in pairs(d.subdomains) do
        new_name(ctx, sub .. "." .. d.domain)
    end
end

function build_url(domain)
    return "https://dns.projectdiscovery.io/dns/" .. domain .. "/subdomains"
end
