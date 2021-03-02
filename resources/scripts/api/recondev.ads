-- Copyright 2017-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "ReconDev"
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

    local resp, err = request(ctx, {
        url=buildurl(domain, c.key),
        headers={['Content-Type']="application/json"},
    })
    if (err ~= nil and err ~= "") then
        return
    end

    local data = json.decode(resp)
    if (data == nil or #data == 0) then
        return
    end

    for i, set in pairs(data) do
        local domains = set["rawDomains"]
        if domains ~= nil and #domains > 0 then
            for j, name in pairs(domains) do
                sendnames(ctx, name)
            end
        end

        local addrs = set["rawIp"]
        if addr ~= nil then
            newaddr(ctx, domain, addr)
        end
    end
end

function buildurl(domain, key)
    return "https://recon.dev/api/search?key=" .. key .. "&domain=" .. domain
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
