-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "HackerTarget"
type = "api"

function start()
    setratelimit(2)
end

function vertical(ctx, domain)
    local resp
    local vurl = buildurl(domain)
    -- Check if the response data is in the graph database
    if (api ~= nil and api.ttl ~= nil and api.ttl > 0) then
        resp = obtain_response(vurl, api.ttl)
    end

    if (resp == nil or resp == "") then
        local err

        resp, err = request({url=vurl})
        if (err ~= nil and err ~= "") then
            return
        end

        if (api ~= nil and api.ttl ~= nil and api.ttl > 0) then
            cache_response(vurl, resp)
        end
    end

    sendnames(ctx, resp)
end

function buildurl(domain)
    return "http://api.hackertarget.com/hostsearch/?q=" .. domain
end

function asn(ctx, addr)
    local resp
    local aurl = asnurl(addr)
    -- Check if the response data is in the graph database
    if (api.ttl ~= nil and api.ttl > 0) then
        resp = obtain_response(aurl, api.ttl)
    end

    if (resp == nil or resp == "") then
        local err

        resp, err = request({url=aurl})
        if (err ~= nil and err ~= "") then
            return
        end

        if (api.ttl ~= nil and api.ttl > 0) then
            cache_response(aurl, resp)
        end
    end

    local j = json.decode("{\"results\": [" .. resp .. "]}")
    if (j == nil or #(j.results) < 4) then
        return
    end

    newasn(ctx, {
        ['addr']=addr,
        asn=tonumber(j.results[2]),
        prefix=j.results[3],
        desc=j.results[4],
    })
end

function asnurl(addr)
    return "https://api.hackertarget.com/aslookup/?q=" .. addr
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
