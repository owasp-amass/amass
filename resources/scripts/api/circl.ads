-- Copyright 2020-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "CIRCL"
type = "api"

function start()
    set_rate_limit(2)
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

    if (c == nil or c.username == nil or 
        c.username == "" or c.password == nil or c.password == "") then
        return
    end

    local resp, err = request(ctx, {
        ['url']="https://www.circl.lu/pdns/query/" .. domain,
        id=c['username'],
        pass=c['password'],
    })
    if (err ~= nil and err ~= "") then
        log(ctx, "vertical request to service failed: " .. err)
        return
    end

    for line in resp:gmatch("([^\n]*)\n?") do
        local j = json.decode(line)

        if (j ~= nil and j.rrname ~= nil and j.rrname ~= "") then
            new_name(ctx, j.rrname)

            if (j.rrtype ~= nil and (j.rrtype == "A" or j.rrtype == "AAAA")) then
                new_addr(ctx, j.rdata, domain)
            else
                send_names(ctx, j.rdata)
            end
        end
    end
end
