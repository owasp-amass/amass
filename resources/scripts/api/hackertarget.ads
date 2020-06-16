-- Copyright 2017 Jeff Foley. All rights reserved.
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

function asn(ctx, addr)
    local page, err = request({url=asnurl(addr)})
    if (err ~= nil and err ~= "") then
        return
    end

    local j = json.decode("{\"results\": [" .. page .. "]}")
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
