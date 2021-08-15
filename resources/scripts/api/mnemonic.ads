-- Copyright 2017-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "Mnemonic"
type = "api"

function start()
    set_rate_limit(1)
end

function vertical(ctx, domain)
    local page, err = request(ctx, {url=build_url(domain)})
    if (err ~= nil and err ~= '') then
        return
    end

    local resp = json.decode(page)
    if (resp == nil or resp.responseCode ~= 200 or resp.count == 0) then
        return
    end

    for i, tb in pairs(resp.data) do
        if in_scope(ctx, tb['query']) then
            new_name(ctx, tb['query'])
            if (tb['rrtype'] == "a" or tb['rrtype'] == "aaaa") then
                new_addr(ctx, tb['answer'], tb['query'])
            end
        end
        if (tb['rrtype'] == "cname") then
            new_name(ctx, tb['answer'])
        end
    end
end

function build_url(domain)
    return "https://api.mnemonic.no/pdns/v3/" .. domain .. "?limit=1000"
end
