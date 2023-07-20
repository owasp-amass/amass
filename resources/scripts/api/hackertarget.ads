-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local json = require("json")

name = "HackerTarget"
type = "api"

function start()
    set_rate_limit(1)
end

function vertical(ctx, domain)
    local c
    local cfg = datasrc_config()
    if (cfg ~= nil) then
        c = cfg.credentials
    end

    local key = ""
    if (c ~= nil and c.key ~= nil and c.key ~= "") then
        key = c.key
    end

    scrape(ctx, {['url']=build_url(domain, key)})
end

function build_url(domain, key)
    local url = "https://api.hackertarget.com/hostsearch/?q=" .. domain
    if (key ~= "") then
        return url .. "&apikey=" .. key
    end
    return url
end

function asn(ctx, addr, asn)
    if addr == "" then
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

    local d = json.decode("{\"results\": [" .. resp.body .. "]}")
    if (d == nil) then
        log(ctx, "failed to decode the JSON response")
        return
    elseif (d.results == nil or #(d.results) < 4) then
        return
    end

    new_asn(ctx, {
        ['addr']=addr,
        ['asn']=tonumber(d.results[2]),
        ['prefix']=d.results[3],
        ['desc']=d.results[4],
    })
end

function asn_url(addr)
    return "https://api.hackertarget.com/aslookup/?q=" .. addr
end
