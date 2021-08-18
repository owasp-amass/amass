-- Copyright 2017-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "ReconDev"
type = "api"

function start()
    set_rate_limit(5)
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

    local data = json.decode(resp)
    if (data == nil or #data == 0) then
        return
    end

    for _, set in pairs(data) do
        local domains = set['rawDomains']
        if domains ~= nil and #domains > 0 then
            for _, name in pairs(domains) do
                new_name(ctx, name)
            end
        end

        local addr = set['rawIp']
        if addr ~= nil then
            new_addr(ctx, addr, domain)
        end
    end
end

function build_url(domain, key)
    return "https://recon.dev/api/search?key=" .. key .. "&domain=" .. domain
end
