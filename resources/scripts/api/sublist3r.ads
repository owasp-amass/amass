-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local json = require("json")

name = "Sublist3rAPI"
type = "api"

function start()
    set_rate_limit(1)
end

function vertical(ctx, domain)
    local resp, err = request(ctx, {['url']=build_url(domain)})
    if (err ~= nil and err ~= "") then
        log(ctx, "vertical request to service failed: " .. err)
        return
    elseif (resp.status_code < 200 or resp.status_code >= 400) then
        log(ctx, "vertical request to service returned with status: " .. resp.status)
        return
    end

    local d = json.decode("{\"subdomains\":" .. resp.body .. "}")
    if (d == nil) then
        log(ctx, "failed to decode the JSON response")
        return
    elseif (d.subdomains == nil or #(d.subdomains) == 0) then
        return
    end

    for _, name in pairs(d.subdomains) do
        if (name ~= nil and name ~= "") then
            new_name(ctx, name)
        end
    end
end

function build_url(domain)
    return "https://api.sublist3r.com/search.php?domain=" .. domain
end
