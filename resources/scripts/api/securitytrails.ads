-- Copyright 2020-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "SecurityTrails"
type = "api"

function start()
    set_rate_limit(2)
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

    local resp, err = request(ctx, {
        ['url']=vert_url(domain),
        headers={['APIKEY']=c.key},
    })
    if (err ~= nil and err ~= "") then
        log(ctx, "vertical request to service failed: " .. err)
        return
    end

    local j = json.decode(resp)
    if (j == nil or #(j.subdomains) == 0) then
        return
    end

    for _, sub in pairs(j.subdomains) do
        new_name(ctx, sub .. "." .. domain)
    end
end

function vert_url(domain)
    return "https://api.securitytrails.com/v1/domain/" .. domain .. "/subdomains"
end

function horizontal(ctx, domain)
    local c
    local cfg = datasrc_config()
    if cfg ~= nil then
        c = cfg.credentials
    end

    if (c == nil or c.key == nil or c.key == "") then
        return
    end

    for i=1,100 do
        local resp, err = request(ctx, {
            ['url']=horizon_url(domain, i),
            headers={['APIKEY']=c.key},
        })
        if (err ~= nil and err ~= "") then
            log(ctx, "horizontal request to service failed: " .. err)
            return
        end

        local j = json.decode(resp)
        if (j == nil or #(j.records) == 0) then
            return
        end

        for _, r in pairs(j.records) do
            if (r.hostname ~= nil and r.hostname ~= "") then
                associated(ctx, domain, r.hostname)
            end
        end
    end
end

function horizon_url(domain, pagenum)
    return "https://api.securitytrails.com/v1/domain/" .. domain .. "/associated?page=" .. pagenum
end
