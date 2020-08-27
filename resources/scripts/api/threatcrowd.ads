-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "ThreatCrowd"
type = "api"

function start()
    setratelimit(10)
end

function vertical(ctx, domain)
    local resp
    local hdrs = {['Content-Type']="application/json"}

    -- Check if the response data is in the graph database
    if (api ~= nil and api.ttl ~= nil and api.ttl > 0) then
        resp = obtain_response(domain, api.ttl)
    end

    if (resp == nil or resp == "") then
        local err
        resp, err = request({
            url=buildurl(domain),
            headers=hdrs,
        })
        if (err ~= nil and err ~= "") then
            return
        end

        if (api ~= nil and api.ttl ~= nil and api.ttl > 0) then
            cache_response(domain, resp)
        end
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

    for i, v in pairs(names) do
        newname(ctx, v)
    end
end
