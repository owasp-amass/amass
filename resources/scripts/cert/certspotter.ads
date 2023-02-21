-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local url = require("url")
local json = require("json")

name = "CertSpotter"
type = "cert"

function start()
    set_rate_limit(2)
end

function vertical(ctx, domain)
    local resp, err = request(ctx, {['url']=api_url(domain)})
    if (err ~= nil and err ~= "") then
        log(ctx, "vertical request to service failed: " .. err)
        return
    elseif (resp.status_code < 200 or resp.status_code >= 400) then
        log(ctx, "vertical request to service returned with status code: " .. resp.status)
        return
    end
    local body = "{\"results\":" .. resp.body .. "}"

    local d = json.decode(body)
    if (d == nil) then
        log(ctx, "failed to decode the JSON response")
        return
    elseif (d.results == nil or #(d.results) == 0) then
        return
    end

    for _, r in pairs(d.results) do
        for _, name in pairs(r['dns_names']) do
            new_name(ctx, name)
        end
    end
end

function api_url(domain)
    local params = {
        ['domain']=domain,
        ['include_subdomains']="true",
        ['match_wildcards']="true",
        ['expand']="dns_names",
    }

    return "https://api.certspotter.com/v1/issuances?" .. url.build_query_string(params)
end
