-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "CIRCL"
type = "api"

function start()
    setratelimit(2)
end

function check()
    if (api ~= nil and api.username ~= nil and 
        api.password ~= nil and api.username ~= "" and api.password ~= "") then
        return true
    end
    return false
end

function vertical(ctx, domain)
    apirequest(ctx, domain)
end

function resolved(ctx, name, domain, records)
    apirequest(ctx, name)
end

function apirequest(ctx, domain)
    if (api == nil or api.username == "" or api.password == "") then
        return
    end

    local page, err = request({
        url=buildurl(domain),
        headers={['Content-Type']="application/json"},
        id=api['username'],
        pass=api['password'],
    })
    if (err ~= nil and err ~= "") then
        return
    end

    for line in page:gmatch("([^\n]*)\n?") do
        local j = json.decode(line)

        if (j ~= nil and j.rrname ~= "") then
            newname(ctx, j.rrname)

            if (j.rrtype == "A" or j.rrtype == "AAAA") then
                newaddr(ctx, j.rdata, domain)
            else
                sendnames(ctx, j.rdata)
            end
        end
    end
end

function buildurl(domain)
    return "https://www.circl.lu/pdns/query/" .. domain
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
