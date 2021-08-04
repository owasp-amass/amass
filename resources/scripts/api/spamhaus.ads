-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "Spamhaus"
type = "api"

function start()
    setratelimit(1)
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

    local token = bearer_token(ctx, c.username, c.password)
    if token == "" then
        return
    end

    local resp, err = request(ctx, {
        url=buildurl(domain),
        headers={
            ['Content-Type']="application/json",
            ['Authorization']="Bearer " .. token,
        },
    })
    if (err ~= nil and err ~= "") then
        return
    end

    local d = json.decode(resp)
    if (d == nil or d.error == true or d.hits == 0) then
        return
    end

    for i, record in pairs(d.records) do
        newname(ctx, record.rrname)
        if (record.rrtype == "A" or record.rrtype == "AAAA") then
             newaddr(ctx, record.rdata, record.rrname)
        end
    end
end

function buildurl(domain)
    return "https://api-pdns.spamhaustech.com/v2/_search/rrset/" .. domain .. "/ANY?stype=rm&limit=1000"
end

function bearer_token(ctx, username, password)
    local body, err = json.encode({
        username=username, 
        password=password,
    })
    if (err ~= nil and err ~= "") then
        return ""
    end

    resp, err = request(ctx, {
        method="POST",
        data=body,
        url="https://api-pdns.spamhaustech.com/v2/login?pretty",
        headers={['Content-Type']="application/json"},
    })
    if (err ~= nil and err ~= "") then
        return ""
    end

    local d = json.decode(resp)
    if (d == nil or d.token == nil or d.token == "") then
        return ""
    end

    return d.token
end
