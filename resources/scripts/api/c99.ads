-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "C99"
type = "api"

function start()
    setratelimit(10)
end

function vertical(ctx, domain)
    if (api == nil or api.key == "") then
        return
    end

    local page, err = request({
        url=buildurl(domain),
        headers={['Content-Type']="application/json"},
    })
    if (err ~= nil and err ~= "") then
        return
    end

    local resp = json.decode(page)
    if (resp == nil or resp.success ~= true or #(resp.subdomains) == 0) then
        return
    end

    for i, s in pairs(resp.subdomains) do
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
