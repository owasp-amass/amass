-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "Spyse"
type = "api"

function start()
    setratelimit(2)
end

function vertical(ctx, domain)
    if (api == nil or api.key == "") then
        return
    end

    local page, err = request({
        url=buildurl(domain),
        headers={['Authorization']="Bearer " .. api.key},
    })
    if (err ~= nil and err ~= "") then
        return
    end

    local resp = json.decode(page)
    if (resp == nil or #(resp['data'].items) == 0) then
        return
    end

    for i, item in pairs(resp['data'].items) do
        sendnames(ctx, item.name)
    end
end

function buildurl(domain)
    return "https://api.spyse.com/v3/data/domain/subdomain?limit=100&domain=" .. domain
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
