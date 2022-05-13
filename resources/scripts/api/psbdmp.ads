-- Copyright 2022 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "PSBDMP"
type = "api"

function start()
    set_rate_limit(1)
end

function vertical(ctx, domain)
    local c
    local cfg = datasrc_config()
    if cfg ~= nil then
        c = cfg.credentials
    end

    local resp, err = request(ctx, {url=search_url(domain)})
    if (err ~= nil and err ~= "") then
        log(ctx, "vertical request to service failed: " .. err)
        return
    end

    send_names(ctx, resp)
    if (c == nil or c.key == nil or c.key == "") then
        return
    end

    local j = json.decode(resp)
    if (j == nil or j.count == nil or j.count == 0) then
        return
    end

    for _, dump in pairs(j.data) do
        local ok = scrape(ctx, {url=dump_url(dump.id, c.key)})
        if not ok then
            return
        end
    end
end

function search_url(domain)
    return "https://psbdmp.ws/api/v3/search/" .. domain
end

function dump_url(id, key)
    return "https://psbdmp.ws/api/v3/dump/" .. id .. "?key=" .. key
end

