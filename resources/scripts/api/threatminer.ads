-- Copyright 2020-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "ThreatMiner"
type = "api"

function start()
    set_rate_limit(8)
end

function vertical(ctx, domain)
    local u = "https://api.threatminer.org/v2/domain.php?q=" .. domain .. "&api=True&rt=5"
    local resp, err = request(ctx, {['url']=u})
    if (err ~= nil and err ~= "") then
        log(ctx, "vertical request to service failed: " .. err)
        return
    end

    local d = json.decode(resp)
    if (d == nil or d['status_code'] ~= "200" or d['status_message'] ~= "Results found." or #(d.results) == 0) then
        return
    end

    for i, sub in pairs(d.results) do
        new_name(ctx, sub)
    end
end
