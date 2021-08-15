-- Copyright 2020-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local url = require("url")
local json = require("json")

name = "CertSpotter"
type = "cert"

function start()
    set_rate_limit(2)
end

function vertical(ctx, domain)
    local page, err = request(ctx, {url=build_url(domain)})
    if (err ~= nil and err ~= "") then
        return
    end

    local resp = json.decode(page)
    if (resp == nil or #resp == 0) then
        return
    end

    for i, r in pairs(resp) do
        for i, name in pairs(r['dns_names']) do
            new_name(ctx, name)
        end
    end
end

function build_url(domain)
    local params = {
        ['domain']=domain,
        ['include_subdomains']="true",
        ['match_wildcards']="true",
        ['expand']="dns_names",
    }

    return "https://api.certspotter.com/v1/issuances?" .. url.build_query_string(params)
end
