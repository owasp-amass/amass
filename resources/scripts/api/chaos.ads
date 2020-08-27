-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "Chaos"
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
    if check() then
        apiquery(ctx, domain)
    end
end

function apiquery(ctx, domain)
    local resp
    local vurl = apiurl(domain)
    -- Check if the response data is in the graph database
    if (api.ttl ~= nil and api.ttl > 0) then
        resp = obtain_response(vurl, api.ttl)
    end

    if (resp == nil or resp == "") then
        local err

        resp, err = request({
            url=vurl,
            headers={['Authorization']=api["key"]},
        })
        if (err ~= nil and err ~= "") then
            return
        end

        if (api.ttl ~= nil and api.ttl > 0) then
            cache_response(vurl, resp)
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
