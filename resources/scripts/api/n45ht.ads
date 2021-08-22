-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "N45HT"
type = "api"

function start()
    set_rate_limit(3)
end

function vertical(ctx, domain)
    local resp, err = request(ctx, {url=build_url(domain)})
    if (err ~= nil and err ~= "") then
        return
    end

    local d = json.decode(resp)
    if (d == nil or #d.subdomains <= 1) then
        return
    end

    for _, sub in pairs(d.subdomains) do
        new_name(ctx, sub)
    end
end

function build_url(domain)
    return "https://api.n45ht.or.id/v1/subdomain-enumeration?domain=" .. domain
end
