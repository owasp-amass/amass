-- Copyright 2020-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

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
    end

    local d = json.decode(resp)
    if (d == nil or d.status_code ~= "200" or #(d.results) == 0) then
        return
    end

    for _, sub in pairs(d.results) do
        new_name(ctx, sub)
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
