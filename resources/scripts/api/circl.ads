-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local json = require("json")

name = "CIRCL"
type = "api"

function start()
    set_rate_limit(2)
end

function check()
    local c
    local cfg = datasrc_config()
    if (cfg ~= nil) then
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
    if (cfg ~= nil) then
        c = cfg.credentials
    end

    if (c == nil or c.username == nil or 
        c.username == "" or c.password == nil or c.password == "") then
        return
    end

    local resp, err = request(ctx, {
        ['url']="https://www.circl.lu/pdns/query/" .. domain,
        ['id']=c.username,
        ['pass']=c.password,
    })
    if (err ~= nil and err ~= "") then
        log(ctx, "vertical request to service failed: " .. err)
        return
    elseif (resp.status_code < 200 or resp.status_code >= 400) then
        log(ctx, "vertical request to service returned with status: " .. resp.status)
        return
    end

    for line in resp.body:gmatch("([^\n]*)\n?") do
        local d = json.decode(line)

        if (d ~= nil and d.rrname ~= nil and d.rrname ~= "") then
            new_name(ctx, d.rrname)

            if (d.rrtype ~= nil and (d.rrtype == "A" or d.rrtype == "AAAA")) then
                new_addr(ctx, d.rdata, domain)
            else
                send_names(ctx, d.rdata)
            end
        end
    end
end
