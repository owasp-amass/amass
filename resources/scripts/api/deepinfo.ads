-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local json = require("json")

name = "Deepinfo"
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

function vertical(ctx, domain)
    local c
    local cfg = datasrc_config()
    if (cfg ~= nil) then
        c = cfg.credentials
    end

    if (c == nil or c.key == nil or c.key == "") then
        return
    end

    local p = 1
    while(true) do
        local resp, err = request(ctx, {
            ['url']=vert_url(domain, p),
            ['header']={
                ['Accept']="application/json",
                ['apikey']=c.key,
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
        elseif (d.results == nil or #(d.results) == 0) then
            return
        end

        for _, r in pairs(d.results) do
            if (r ~= nil and r.punycode ~= nil and r.punycode ~= "") then
                new_name(ctx, r.punycode)
            end
        end

        if (d.result_count <= 100 * p) then
            break
        end
        p = p + 1
    end
end

function vert_url(domain, pagenum)
    return "https://api.deepinfo.com/v1/discovery/subdomain-finder?domain=" .. domain .. "&page=" .. pagenum
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

    local p = 1
    while(true) do
        local resp, err = request(ctx, {
            ['url']=horizon_url(domain, p),
            ['header']={
                ['Accept']="application/json",
                ['apikey']=c.key,
            },
        })
        if (err ~= nil and err ~= "") then
            log(ctx, "horizontal request to service failed: " .. err)
            return
        elseif (resp.status_code < 200 or resp.status_code >= 400) then
            log(ctx, "horizontal request to service returned with status: " .. resp.status)
            return
        end

        local d = json.decode(resp.body)
        if (d == nil) then
            log(ctx, "failed to decode the JSON response")
            return
        elseif (d.results == nil or #(d.results) == 0) then
            return
        end

        for _, r in pairs(d.results) do
            if (r ~= nil and r.punycode ~= nil and r.punycode ~= "") then
                associated(ctx, domain, r.punycode)
            end
        end

        if (d.result_count <= 100 * i) then
            break
        end
        p = p + 1
    end
end

function horizon_url(domain, pagenum)
    return "https://api.deepinfo.com/v1/discovery/associated-domain-finder?domain=" .. domain .. "&page=" .. pagenum
end

function asn(ctx, addr, asn)
    local c
    local cfg = datasrc_config()
    if (cfg ~= nil) then
        c = cfg.credentials
    end

    if (c == nil or c.key == nil or c.key == "") then
        return
    end

    if (addr == nil or addr == "") then
        return
    end

    local resp, err = request(ctx, {
        ['url']=asn_url(addr),
        ['header']={
            ['Accept']="application/json",
            ['apikey']=c.key,
        },
    })
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
    elseif (d.ipwhois == nil) then
        return
    end

    new_asn(ctx, {
        ['addr']=addr,
        ['asn']=tonumber(string.sub(d.ipwhois.asn, 3)),
        ['desc']=d.ipwhois.asn_description,
        ['prefix']=d.ipwhois.asn_cidr,
        ['cc']=d.ipwhois.asn_country_code,
        ['registry']=d.ipwhois.asn_registry,
    })
end

function asn_url(addr)
    return "https://api.deepinfo.com/v1/lookup/ip-whois?ip=" .. addr
end
