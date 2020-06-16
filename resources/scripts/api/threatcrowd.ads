-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "ThreatCrowd"
type = "api"

function start()
    setratelimit(10)
end

function vertical(ctx, domain)
    local hdrs = {['Content-Type']="application/json"}

    local page, err = request({
        url=buildurl(domain),
        headers=hdrs,
    })
    if (err ~= nil and err ~= '') then
        return
    end

    local resp = json.decode(page)
    if (resp == nil or resp.response_code ~= "1" or #(resp.subdomains) == 0) then
        return
    end

    for i, sub in pairs(resp.subdomains) do
        sendnames(ctx, sub)
    end

    for i, tb in pairs(resp.resolutions) do
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

    for i, v in pairs(names) do
        newname(ctx, v)
    end
end
