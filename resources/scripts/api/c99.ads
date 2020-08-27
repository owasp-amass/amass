-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "C99"
type = "api"

function start()
    setratelimit(10)
end

function check()
    if (api ~= nil and api.key ~= nil and api.key ~= "") then
        return true
    end
    return false
end

function vertical(ctx, domain)
    if (api == nil or api.key == nil or api.key == "") then
        return
    end

    local resp
    local vurl = buildurl(domain)
    -- Check if the response data is in the graph database
    if (api.ttl ~= nil and api.ttl > 0) then
        resp = obtain_response(vurl, api.ttl)
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

        if (api.ttl ~= nil and api.ttl > 0) then
            cache_response(vurl, resp)
        end
    end

    local d = json.decode(resp)
    if (d == nil or d.success ~= true or #(d.subdomains) == 0) then
        return
    end

    for i, s in pairs(d.subdomains) do
        sendnames(ctx, s.subdomain)
    end
end

function buildurl(domain)
    return "https://api.c99.nl/subdomainfinder?key=" .. api.key .. "&domain=" .. domain .. "&json"
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
