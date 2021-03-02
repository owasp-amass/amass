-- Copyright 2017-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "ThreatCrowd"
type = "api"

function start()
    setratelimit(10)
end

function vertical(ctx, domain)
    local c
    local cfg = datasrc_config()
    if cfg ~= nil then
        c = cfg.credentials
    end

    local resp, err = request(ctx, {
        url=buildurl(domain),
        headers={['Content-Type']="application/json"},
    })
    if (err ~= nil and err ~= "") then
        return
    end

    local d = json.decode(resp)
    if (d == nil or d.response_code ~= "1" or #(d.subdomains) == 0) then
        return
    end

    for i, sub in pairs(d.subdomains) do
        sendnames(ctx, sub)
    end

    for i, tb in pairs(d.resolutions) do
        newaddr(ctx, tb.ip_address, domain)
    end
end

function buildurl(domain)
    return "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=" .. domain
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
