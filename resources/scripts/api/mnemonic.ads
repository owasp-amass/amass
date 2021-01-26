-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "Mnemonic"
type = "api"

function start()
    setratelimit(1)
end

function vertical(ctx, domain)
    local page, err = request(ctx, {url=apiurl(domain)})
    if (err ~= nil and err ~= '') then
        return
    end

    local resp = json.decode(page)
    if (resp == nil or resp["responseCode"] ~= 200) then
        return
    end

    for i, tb in pairs(resp.data) do
        if ((tb.rrtype == "a" or tb.rrtype == "aaaa") and inscope(ctx, tb.query)) then
            newname(ctx, tb.query)
            newaddr(ctx, tb.answer, tb.query)
        end
    end
end

function apiurl(domain)
    return "https://api.mnemonic.no/pdns/v3/" .. domain
end
