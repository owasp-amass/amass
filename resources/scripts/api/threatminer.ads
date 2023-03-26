-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local url = require("url")
local json = require("json")

name = "ThreatMiner"
type = "api"

function start()
    set_rate_limit(8)
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

    local d = json.decode(resp.body)
    if (d == nil) then
        log(ctx, "failed to decode the JSON response")
        return
    elseif (d.status_code ~= "200" or d.results == nil or #(d.results) == 0) then
        return
    end

    for _, sub in pairs(d.results) do
        if (sub ~= nil and sub ~= "") then
            new_name(ctx, sub)
        end
    end
end

function build_url(domain)
    local params = {
        ['rt']="5",
        ['q']=domain,
        ['api']="True",
    }
    return "https://api.threatminer.org/v2/domain.php?" .. url.build_query_string(params)
end
