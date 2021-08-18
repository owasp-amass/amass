-- Copyright 2017-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "Hunter"
type = "api"

function start()
    set_rate_limit(1)
end

function check()
    local c
    local cfg = datasrc_config()
    if cfg ~= nil then
        c = cfg.credentials
    end

    if (c ~= nil and c.key ~= nil and c.key ~= "") then
        return true
    end
    return false
end

function vertical(ctx, domain)
    local c
    local cfg = datasrc_config()
    if cfg ~= nil then
        c = cfg.credentials
    end

    if (c == nil or c.key == nil or c.key == "") then
        return
    end

    local resp, err = request(ctx, {url=build_url(domain, c.key)})
    if (err ~= nil and err ~= "") then
        return
    end

    local j = json.decode(resp)
    if (j == nil or j.data == nil or #j['data'].emails == 0) then
        return
    end

    for _, email in pairs(j['data'].emails) do
        for _, src in pairs(email.sources) do
            new_name(ctx, src.domain)
        end
    end
end

function build_url(domain, key)
    return "https://api.hunter.io/v2/domain-search?domain=" .. domain .. "&api_key=" .. key
end
