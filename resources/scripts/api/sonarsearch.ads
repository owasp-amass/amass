-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "SonarSearch"
type = "api"

function start()
    setratelimit(1)
end

function vertical(ctx, domain)
    local p = 0
    while(true) do
        local resp, err = request(ctx, {url=buildurl(domain, p)})
        if (err ~= nil and err ~= "") then
            return
        end

        local d = json.decode(resp)
        if (d == nil or #d == 0) then
            return
        end

        sendnames(ctx, resp)
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
