-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "DNSlytics"
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

    if (c ~= nil and c.key ~= nil and c.key ~= "") then
        return true
    end
    return false
end

function horizontal(ctx, domain)
    local c
    local cfg = datasrc_config()
    if cfg ~= nil then
        c = cfg.credentials
    end

    if (c == nil or c.key == nil or c.key == "") then
        return
    end

    -- DNSlytics ReverseIP API
    local resp, err = request(ctx, {url=firsturl(domain, c.key)})
    if (err ~= nil and err ~= "") then
        return
    end

    local d = json.decode(resp)
    if (d == nil or d.data == nil or d.data['domains'] == nil) then
        return
    end

    for i, name in pairs(d.data['domains']) do
        associated(ctx, domain, name)
    end

    -- DNSlytics ReverseGAnalytics API
    resp, err = request(ctx, {url=secondurl(domain, c.key)})
    if (err ~= nil and err ~= "") then
        return
    end

    d = json.decode(resp)
    if (d == nil or d.data == nil or d.data['domains'] == nil) then
        return
    end

    for i, res in pairs(d.data['domains']) do
        associated(ctx, domain, res['domain'])
    end
end

function firsturl(domain, key)
    return "https://api.dnslytics.net/v1/reverseip/" .. domain .. "?apikey=" .. key
end

function secondurl(domain, key)
    return "https://api.dnslytics.net/v1/reverseganalytics/" .. domain .. "?apikey=" .. key
end

function asn(ctx, addr, asn)
    if addr == "" then
        return
    end

    local resp, err = request(ctx, {url=asnurl(addr)})
    if (err ~= nil and err ~= "") then
        return
    end

    local d = json.decode(resp)
    if (d == nil or d.announced == false) then
        return
    end

    local desc = d.shortname .. ", " .. d.country
    newasn(ctx, {
        ['addr']=d.ip,
        ['asn']=d.asn,
        ['desc']=desc,
        ['prefix']=d.cidr,
    })
end

function asnurl(addr)
    return "https://freeapi.dnslytics.net/v1/ip2asn/" .. addr
end
