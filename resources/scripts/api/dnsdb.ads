-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local json = require("json")

name = "DNSDB"
type = "api"

local rrtypes = {"A", "AAAA", "CNAME", "NS", "MX"}

function start()
    set_rate_limit(1)
end

function check()
    local c
    local cfg = datasrc_config()
    if (cfg ~= nil) then
        c = cfg.credentials
    end

    if (c ~= nil and c.key ~= nil and c.key ~= "") then
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

    if (c == nil or c.key == nil or c.key == "") then
        return
    end

    local ts = oldest_timestamp()
    for _, rrtype in ipairs(rrtypes) do
        local url = build_url(domain, rrtype)

        query(ctx, url, ts, c.key)
    end
end

function oldest_timestamp()
    local temp = os.date("*t", os.time())

    temp['year'] = temp['year'] - 1
    return os.time(temp)
end

function query(ctx, url, ts, key)
    local resp, err = request(ctx, {
        ['url']=url,
        ['header']={
            ['X-API-Key']=key,
            ['Accept']="application/x-ndjson",
        },
    })
    if (err ~= nil and err ~= "") then
        log(ctx, "vertical request to service failed: " .. err)
        return
    elseif (resp.status_code < 200 or resp.status_code >= 400) then
        log(ctx, "vertical request to service returned with status: " .. resp.status)
        return
    end

    for line in magiclines(resp.body) do
        local d = json.decode(line)

        if (d ~= nil and d['obj'] ~= nil) then
            local obj = d['obj']

            if (obj.rrname ~= nil and obj.rrname ~= "" and 
                obj.time_last ~= nil and obj.time_last >= ts) then
                new_name(ctx, obj.rrname)
            end
        end
    end
end

function build_url(domain, rrtype)
    return "https://api.dnsdb.info/dnsdb/v2/lookup/rrset/name/*." .. domain .. "/" .. rrtype .. "?limit=0"
end

function magiclines(str)
    local pos = 1;

    return function()
        if (not pos) then return nil end

        local line
        local  p1, p2 = string.find(str, "\r?\n", pos)
        if p1 then
            line = str:sub(pos, p1 - 1)
            pos = p2 + 1
        else
            line = str:sub(pos)
            pos = nil
        end

        return line
    end
end
