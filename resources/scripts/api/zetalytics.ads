-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "ZETAlytics"
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

    local resp
    local vurl = buildurl(domain, c.key)
    -- Check if the response data is in the graph database
    if (cfg.ttl ~= nil and cfg.ttl > 0) then
        resp = obtain_response(domain, cfg.ttl)
    end

    if (resp == nil or resp == "") then
        local err

        resp, err = request({
            url=vurl,
            headers={['Content-Type']="application/json"},
        })
        if (err ~= nil and err ~= "") then
            return
        end

        if (cfg.ttl ~= nil and cfg.ttl > 0) then
            cache_response(domain, resp)
        end
    end

    local d = json.decode(resp)
    if (d == nil or #(d.results) == 0) then
        return
    end

    for i, r in pairs(d.results) do
        sendnames(ctx, r.qname)
    end
end

function buildurl(domain, key)
    return "https://zonecruncher.com/api/v1/subdomains?q=" .. domain .. "&token=" .. key
end

function sendnames(ctx, content)
    local names = find(content, subdomainre)
    if names == nil then
        return
    end

    for i, v in pairs(names) do
        newname(ctx, v)
    end
end
