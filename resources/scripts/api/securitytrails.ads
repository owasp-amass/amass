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

    local vurl = "https://api.securitytrails.com/v1/domain/" .. domain .. "/subdomains"
    local resp, err = request(ctx, {
        ['url']=vurl,
        headers={APIKEY=c.key},
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

function horizontal(ctx, domain)
    local c
    local cfg = datasrc_config()
    if cfg ~= nil then
        c = cfg.credentials
    end

    if (c == nil or c.key == nil or c.key == "") then
        return
    end

    local hurl = "https://api.securitytrails.com/v1/domain/" .. domain .. "/associated"
    local resp, err = request(ctx, {
        ['url']=hurl,
        headers={APIKEY=c.key},
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
