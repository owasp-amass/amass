-- Copyright 2022 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")
local url = require("url")

name = "Pulsedive"
type = "api"

function start()
    set_rate_limit(2)
end

function vertical(ctx, domain)
    local c
    local cfg = datasrc_config()
    if cfg ~= nil then
        c = cfg.credentials
    end

    local key
    local limit = 100
    if (c ~= nil and c.key ~= nil and c.key ~= "") then
        key = c.key
        limit = 1000
    end

    local resp, err = request(ctx, {['url']=build_url(domain, key, limit)})
    if (err ~= nil and err ~= "") then
        log(ctx, "vertical request to service failed: " .. err)
        return
    end

    local j = json.decode(resp)
    if (j == nil or j.results == nil) then
        return
    end

    for _, r in pairs(j.results) do
        new_name(ctx, r.indicator)
    end
end

function build_url(domain, key, limit)
    local query = "type=domain and ioc=*." .. domain
    local params = {
        ['search']="indicators",
        ['limit']=limit,
        ['q']=query,
        ['key']=key,
    }

    return "https://pulsedive.com/api/explore.php?" .. url.build_query_string(params)
end
