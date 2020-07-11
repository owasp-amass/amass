-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "ZETAlytics"
type = "api"

function start()
    setratelimit(5)
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
    if (resp == nil or #(resp.results) == 0) then
        return
    end

    for i, r in pairs(resp.results) do
        sendnames(ctx, r.qname)
    end
end

function buildurl(domain)
    return "https://zonecruncher.com/api/v1/subdomains?q=" .. domain .. "&token=" .. api.key
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
