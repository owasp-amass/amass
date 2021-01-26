-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "Chaos"
type = "api"

function start()
    setratelimit(10)
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

    local resp
    local vurl = apiurl(domain)
    -- Check if the response data is in the graph database
    if (cfg.ttl ~= nil and cfg.ttl > 0) then
        resp = obtain_response(domain, cfg.ttl)
    end

    if (resp == nil or resp == "") then
        local err

        resp, err = request(ctx, {
            url=vurl,
            headers={['Authorization']=c["key"]},
        })
        if (err ~= nil and err ~= "") then
            return
        end

        if (cfg.ttl ~= nil and cfg.ttl > 0) then
            cache_response(domain, resp)
        end
    end

    local d = json.decode(resp)
    if (d == nil or #(d.subdomains) == 0) then
        return
    end

    for i, sub in pairs(d.subdomains) do
        newname(ctx, sub .. "." .. d.domain)
    end
end

function apiurl(domain)
    return "https://dns.projectdiscovery.io/dns/" .. domain .. "/subdomains"
end
