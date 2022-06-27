-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "Detectify"
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

    -- Check if the asset has been monitored already
    local token, err = get_asset_token(ctx, domain, key)
    if err ~= nil then
        log(ctx, "get_asset_token request to service failed: " .. err)
        return
    end

    if token == nil then
        -- Add new asset to the team
        token = add_asset(ctx, domain, key)
        if token == nil then
            return
        end

        -- Wait a bit for Detectify to enumerate subdomains
        for i=1,90 do check_rate_limit() end
    end

    get_subdomains(ctx, token, key)
end

function get_asset_token(ctx, domain, key)
    local resp, err = request(ctx, {
        ['url']="https://api.detectify.com/rest/v2/assets/",
        ['headers']={['X-Detectify-Key']=key},
    })
    local j = json.decode(resp)

    if (err ~= nil and err ~= "") then
        if (j ~= nil and j.error ~= nil) then
            err = j.error.message
        end

        return nil, err
    end

    for _, a in pairs(j.assets) do
        if a.name == domain then
            return a.token, nil
        end
    end
    return nil, nil
end

function add_asset(ctx, domain, key)
    local body, err = json.encode({['name']=domain})
    if (err ~= nil and err ~= "") then
        return
    end

    local resp, err = request(ctx, {
        ['url']="https://api.detectify.com/rest/v2/assets/",
        ['method']="POST",
        ['data']=body,
        ['headers']={['X-Detectify-Key']=c.key},
    })
    local j = json.decode(resp)

    if (err ~= nil and err ~= "") then
        if (j ~= nil and j.error ~= nil) then
            err = j.error.message
        end

        log(ctx, "add_asset request to service failed: " .. err)
        return
    end

    return j.token
end

function get_subdomains(ctx, token, key)
    local resp, err = request(ctx, {
        ['url']=build_url(token),
        ['headers']={['X-Detectify-Key']=key},
    })
    local j = json.decode(resp)

    if (err ~= nil and err ~= "") then
        if (j ~= nil and j.error ~= nil) then
            err = j.error.message
        end

        log(ctx, "get_subdomains request to service failed: " .. err)
        return
    end

    for _, a in pairs(j.assets) do
        new_name(ctx, s.name)
    end
end

function build_url(token)
    return "https://api.detectify.com/rest/v2/assets/" .. token .. "/subdomains/"
end
