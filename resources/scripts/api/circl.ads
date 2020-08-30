-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "CIRCL"
type = "api"

function start()
    setratelimit(2)
end

function check()
    local c
    local cfg = datasrc_config()
    if cfg ~= nil then
        c = cfg.credentials
    end

    if (c ~= nil and c.username ~= nil and 
        c.password ~= nil and c.username ~= "" and c.password ~= "") then
        return true
    end
    return false
end

function vertical(ctx, domain)
    local c
    local cfg = datasrc_config()
    if cfg ~= nil then
        c = cfg.credentials
    end

    if (c == nil or c.username == "" or c.password == "") then
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
