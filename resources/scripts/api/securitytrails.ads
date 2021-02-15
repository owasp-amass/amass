-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "SecurityTrails"
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

    if (c == nil or c.key == nil or c.key == "") then
        return
    end

    local resp
    local vurl = verturl(domain)
    -- Check if the response data is in the graph database
    if (cfg.ttl ~= nil and cfg.ttl > 0) then
        resp = obtain_response(vurl, cfg.ttl)
    end

    if (resp == nil or resp == "") then
        local err

        resp, err = request(ctx, {
            url=vurl,
            headers={
                APIKEY=c.key,
                ['Content-Type']="application/json",
            },
        })
        if (err ~= nil and err ~= "") then
            return
        end

        if (cfg.ttl ~= nil and cfg.ttl > 0) then
            cache_response(vurl, resp)
        end
    end

    local j = json.decode(resp)
    if (j == nil or #(j.subdomains) == 0) then
        return
    end

    for i, sub in pairs(j.subdomains) do
        sendnames(ctx, sub .. "." .. domain)
    end
end

function verturl(domain)
    return "https://api.securitytrails.com/v1/domain/" .. domain .. "/subdomains"
end

function sendnames(ctx, content)
    local names = find(content, subdomainre)
    if (names == nil) then
        return
    end

    local found = {}
    for i, v in pairs(names) do
        if (found[v] == nil) then
            newname(ctx, v)
            found[v] = true
        end
    end
end

function horizontal(ctx, domain)
    local c
    local cfg = datasrc_config()
    if cfg ~= nil then
        c = cfg.credentials
    end

    if (c == nil or c.key == "") then
        return
    end

    local resp
    local hurl = horizonurl(domain)
    -- Check if the response data is in the graph database
    if (cfg.ttl ~= nil and cfg.ttl > 0) then
        resp = obtain_response(hurl, cfg.ttl)
    end

    if (resp == nil or resp == "") then
        local err

        resp, err = request(ctx, {
            url=hurl,
            headers={
                APIKEY=c.key,
                ['Content-Type']="application/json",
            },
        })
        if (err ~= nil and err ~= "") then
            return
        end

        if (cfg.ttl ~= nil and cfg.ttl > 0) then
            cache_response(hurl, resp)
        end
    end

    local j = json.decode(resp)
    if (j == nil or #(j.records) == 0) then
        return
    end

    for i, r in pairs(j.records) do
        if (r.hostname ~= "") then
            associated(ctx, domain, r.hostname)
        end
    end
end

function horizonurl(domain)
    return "https://api.securitytrails.com/v1/domain/" .. domain .. "/associated"
end
