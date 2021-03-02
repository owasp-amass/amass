-- Copyright 2017-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "Shodan"
type = "api"

function start()
    setratelimit(2)
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

    local vurl = buildurl(domain, c.key)
    local resp, err = request(ctx, {
        url=vurl,
        headers={['Content-Type']="application/json"},
    })
    if (err ~= nil and err ~= "") then
        return
    end

    local d = json.decode(resp)
    if (d == nil or #(d.subdomains) == 0) then
        return
    end

    for i, sub in pairs(d.subdomains) do
        sendnames(ctx, sub .. "." .. domain)
    end
end

function buildurl(domain, key)
    return "https://api.shodan.io/dns/domain/" .. domain .. "?key=" .. key
end

function sendnames(ctx, content)
    local names = find(content, subdomainre)
    if names == nil then
        return
    end

    local found = {}
    for i, v in pairs(names) do
        if found[v] == nil then
            newname(ctx, v)
            found[v] = true
        end
    end
end
