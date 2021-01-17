-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "SonarSearch"
type = "api"

function start()
    setratelimit(3)
end

function vertical(ctx, domain)
    local p = 0
    local cfg = datasrc_config()

    while(true) do
        local resp
        local vurl = buildurl(domain, p)
        -- Check if the response data is in the graph database
        if (cfg.ttl ~= nil and cfg.ttl > 0) then
            resp = obtain_response(vurl, cfg.ttl)
        end

        if (resp == nil or resp == "") then
            resp, err = request({url=vurl})
            if (err ~= nil and err ~= "") then
                return
            end

            if (cfg.ttl ~= nil and cfg.ttl > 0) then
                cache_response(vurl, resp)
            end
        end

        local d = json.decode(resp)
        if (d == nil or #d == 0) then
            return
        end

        sendnames(ctx, resp)
        checkratelimit()
        p = p + 1
    end
end

function buildurl(domain, page)
    return "https://sonar.omnisint.io/subdomains/" .. domain .. "?page=" .. page
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
