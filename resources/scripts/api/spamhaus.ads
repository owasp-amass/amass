-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local json = require("json")

name = "Spamhaus"
type = "api"

function start()
    set_rate_limit(1)
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

    local token = bearer_token(ctx, c.username, c.password)
    if (token == "") then
        return
    end

    local resp, err = request(ctx, {
        ['url']=build_url(domain),
        ['header']={
            ['Accept']="application/json",
            ['Content-Type']="application/json",
            ['Authorization']="Bearer " .. token,
        },
    })
    if (err ~= nil and err ~= "") then
        log(ctx, "vertical request to service failed: " .. err)
        return
    elseif (resp.status_code < 200 or resp.status_code >= 400) then
        log(ctx, "vertical request to service returned with status: " .. resp.status)
        return
    end

    local d = json.decode(resp.body)
    if (d == nil) then
        log(ctx, "failed to decode the JSON response")
        return
    elseif (d.error ~= nil and d.error == true) then
        log(ctx, "error returned in the JSON response")
        return
    elseif (d.hits == nil or d.hits == 0 or d.results == nil) then
        return
    end

    for _, r in pairs(d.records) do
        if (r.rrname ~= nil and r.rrname ~= "") then
            new_name(ctx, r.rrname)
        end
        if (r.rrtype ~= nil and (r.rrtype == "A" or r.rrtype == "AAAA")) then
             new_addr(ctx, r.rdata, r.rrname)
        end
    end
end

function build_url(domain)
    return "https://api-pdns.spamhaustech.com/v2/_search/rrset/" .. domain .. "/ANY?stype=rm&limit=1000"
end

function bearer_token(ctx, username, password)
    local body, err = json.encode({
        ['username']=username, 
        ['password']=password,
    })
    if (err ~= nil and err ~= "") then
        return ""
    end

    local resp, err = request(ctx, {
        ['url']="https://api-pdns.spamhaustech.com/v2/login",
        ['method']="POST",
        ['header']={
            ['Accept']="application/json",
            ['Content-Type']="application/json",
        },
        ['body']=body,
    })
    if (err ~= nil and err ~= "") then
        log(ctx, "bearer_token request to service failed: " .. err)
        return ""
    elseif (resp.status_code < 200 or resp.status_code >= 400) then
        log(ctx, "bearer_token request to service returned with status: " .. resp.status)
        return ""
    end

    local d = json.decode(resp.body)
    if (d == nil) then
        log(ctx, "failed to decode the bearer_token response")
        return ""
    elseif (d.token == nil or d.token == "") then
        log(ctx, "the bearer_token response did not include the token data")
        return ""
    end

    return d.token
end
