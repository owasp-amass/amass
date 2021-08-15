-- Copyright 2020-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "ThreatCrowd"
type = "api"

function start()
    set_rate_limit(10)
end

function vertical(ctx, domain)
    local resp, err = request(ctx, {url=build_url(domain)})
    if (err ~= nil and err ~= "") then
        return
    end

    local d = json.decode(resp)
    if (d == nil or d.response_code ~= "1" or #d.subdomains == 0) then
        return
    end

    for i, sub in pairs(d.subdomains) do
        new_name(ctx, sub)
    end

    for i, tb in pairs(d.resolutions) do
        new_addr(ctx, tb.ip_address, domain)
    end
end

function build_url(domain)
    return "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=" .. domain
end
