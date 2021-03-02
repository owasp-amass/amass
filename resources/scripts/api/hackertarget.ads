-- Copyright 2017-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "HackerTarget"
type = "api"

function start()
    setratelimit(1)
end

function vertical(ctx, domain)
    scrape(ctx, {url=buildurl(domain)})
end

function buildurl(domain)
    return "http://api.hackertarget.com/hostsearch/?q=" .. domain
end

function asn(ctx, addr, asn)
    if addr == "" then
        return
    end

    local aurl = asnurl(addr)
    local resp, err = request(ctx, {url=aurl})
    if (err ~= nil and err ~= "") then
        return
    end

    local j = json.decode("{\"results\": [" .. resp .. "]}")
    if (j == nil or #(j.results) < 4) then
        return
    end

    newasn(ctx, {
        ['addr']=addr,
        asn=tonumber(j.results[2]),
        prefix=j.results[3],
        desc=j.results[4],
    })
end

function asnurl(addr)
    return "https://api.hackertarget.com/aslookup/?q=" .. addr
end
