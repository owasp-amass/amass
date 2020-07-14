-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "BufferOver"
type = "api"

function start()
    setratelimit(1)
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
    return "https://dns.bufferover.run/dns?q=." .. domain
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
