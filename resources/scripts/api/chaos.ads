-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "Chaos"
type = "api"

function start()
    setratelimit(10)
end

function vertical(ctx, domain)
    if (api ~= nil and api.key ~= '') then
        apiquery(ctx, domain)
    end
end

function apiquery(ctx, domain)
    local page, err = request({
        url=apiurl(domain),
        headers={['Authorization']=api["key"]},
    })
    if (err ~= nil and err ~= '') then
        return
    end

    local resp = json.decode(page)
    if (resp == nil or #(resp.subdomains) == 0) then
        return
    end

    for i, sub in pairs(resp.subdomains) do
        newname(ctx, sub .. "." .. resp.domain)
    end
end

function apiurl(domain)
    return "https://dns.projectdiscovery.io/dns/" .. domain .. "/subdomains"
end
