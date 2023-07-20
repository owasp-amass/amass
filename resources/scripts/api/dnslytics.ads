-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local json = require("json")

name = "DNSlytics"
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

    if (c ~= nil and c.key ~= nil and c.key ~= "") then
        return true
    end
    return false
end

function horizontal(ctx, domain)
    local c
    local cfg = datasrc_config()
    if (cfg ~= nil) then
        c = cfg.credentials
    end

    if (c == nil or c.key == nil or c.key == "") then
        return
    end

    -- DNSlytics ReverseIP API
    local resp, err = request(ctx, {['url']=first_url(domain, c.key)})
    if (err ~= nil and err ~= "") then
        log(ctx, "first horizontal request to service failed: " .. err)
        return
    elseif (resp.status_code < 200 or resp.status_code >= 400) then
        log(ctx, "first horizontal request to service returned with status: " .. resp.status)
        return
    end

    local d = json.decode(resp.body)
    if (d == nil) then
        log(ctx, "failed to decode the JSON first response")
        return
    elseif (d.data == nil or d['data'].domains == nil or #(d['data'].domains) == 0) then
        return
    end

    for _, name in pairs(d['data'].domains) do
        if (name ~= nil and name ~= "") then
            associated(ctx, domain, name)
        end
    end

    -- DNSlytics ReverseGAnalytics API
    resp, err = request(ctx, {['url']=second_url(domain, c.key)})
    if (err ~= nil and err ~= "") then
        log(ctx, "second horizontal request to service failed: " .. err)
        return
    elseif (resp.status_code < 200 or resp.status_code >= 400) then
        log(ctx, "second horizontal request to service returned with status: " .. resp.status)
        return
    end

    d = json.decode(resp.body)
    if (d == nil) then
        log(ctx, "failed to decode the JSON second response")
        return
    elseif (d.data == nil or d['data'].domains == nil or #(d['data'].domains) == 0) then
        return
    end

    for _, res in pairs(d['data'].domains) do
        if (res ~= nil and res.domain ~= nil and res.domain ~= "") then
            associated(ctx, domain, res.domain)
        end
    end
end

function first_url(domain, key)
    return "https://api.dnslytics.net/v1/reverseip/" .. domain .. "?apikey=" .. key
end

function second_url(domain, key)
    return "https://api.dnslytics.net/v1/reverseganalytics/" .. domain .. "?apikey=" .. key
end

function asn(ctx, addr, asn)
    if (addr == "") then
        return
    end

    local resp, err = request(ctx, {['url']=asn_url(addr)})
    if (err ~= nil and err ~= "") then
        log(ctx, "asn request to service failed: " .. err)
        return
    elseif (resp.status_code < 200 or resp.status_code >= 400) then
        log(ctx, "asn request to service returned with status: " .. resp.status)
        return
    end

    local d = json.decode(resp.body)
    if (d == nil) then
        log(ctx, "failed to decode the JSON response")
        return
    elseif (d.announced == nil or not d.announced) then
        return
    end

    new_asn(ctx, {
        ['addr']=d.ip,
        ['asn']=d.asn,
        ['desc']=d.shortname .. ", " .. d.country,
        ['prefix']=d.cidr,
    })
end

function asn_url(addr)
    return "https://freeapi.dnslytics.net/v1/ip2asn/" .. addr
end
