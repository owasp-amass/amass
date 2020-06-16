-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "BinaryEdge"
type = "api"

function start()
    setratelimit(2)
end

function vertical(ctx, domain)
    if (api ~= nil and api.key ~= '') then
        apiquery(ctx, domain)
    end
end

function apiquery(ctx, domain)
    local hdrs={
        ['X-KEY']=api["key"],
        ['Content-Type']="application/json",
    }

    while(true) do
        local page, err = request({
            url=apiurl(domain),
            headers=hdrs,
        })
        if (err ~= nil and err ~= '') then
            return
        end
    
        local resp = json.decode(page)
        if (resp == nil or #(resp.events) == 0) then
            return
        end
    
        for i, v in pairs(resp.events) do
            newname(ctx, v)
        end

        if (resp.page > 500 or resp.page > (resp.total / resp.pagesize)) then
            return
        end
    end
end

function apiurl(domain)
    return "https://api.binaryedge.io/v2/query/domains/subdomain/" .. domain
end
