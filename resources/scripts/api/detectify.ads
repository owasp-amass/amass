-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local json = require("json")

name = "Detectify"
type = "api"

function start()
    set_rate_limit(1)
end

function check()
    local c
    local cfg = datasrc_config()
    if (cfg ~= nil) then
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
    if (cfg ~= nil) then
        c = cfg.credentials
    end

    if (c == nil or c.key == nil or c.key == "") then
        return
    end

    -- Check if the asset has been monitored already
    local token, err = get_asset_token(ctx, domain, key)
    if (err ~= nil) then
        log(ctx, "get_asset_token request to service failed: " .. err)
        return
    end

    if (token == nil) then
        -- Add new asset to the team
        token = add_asset(ctx, domain, key)
        if (token == nil) then
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
        ['header']={['X-Detectify-Key']=key},
    })
    if (err ~= nil and err ~= "") then
        return nil, "get_asset_token request to service failed: " .. err
    elseif (resp.status_code < 200 or resp.status_code >= 400) then
        return nil, "get_asset_token request to service returned with status: " .. resp.status
    end

    local d = json.decode(resp.body)
    if (d == nil) then
        return nil, "failed to decode the JSON response"
    elseif (d.error ~= nil) then
        if (d['error'].message ~= nil and d['error'].message ~= "") then
            err = d['error'].message
        end
        return nil, err
    elseif (d.assets == nil or #(d.assets) == 0) then
        return nil, nil
    end

    for _, a in pairs(d.assets) do
        if (a.name == domain and a.token ~= nil and a.token ~= "") then
            return a.token, nil
        end
    end
    return nil, nil
end

function add_asset(ctx, domain, key)
    local body, err = json.encode({['name']=domain})
    if (err ~= nil and err ~= "") then
        return nil
    end

    local resp, err = request(ctx, {
        ['url']="https://api.detectify.com/rest/v2/assets/",
        ['method']="POST",
        ['header']={['X-Detectify-Key']=c.key},
        ['body']=body,
    })
    if (err ~= nil and err ~= "") then
        log(ctx, "add_asset request to service failed: " .. err)
        return
    elseif (resp.status_code < 200 or resp.status_code >= 400) then
        log(ctx, "add_asset request to service returned with status: " .. resp.status)
        return
    end

    local d = json.decode(resp.body)
    if (d == nil or d.token == nil or d.token == "") then
        return nil
    end

    return d.token
end

function get_subdomains(ctx, token, key)
    local resp, err = request(ctx, {
        ['url']=build_url(token),
        ['header']={['X-Detectify-Key']=key},
    })
    if (err ~= nil and err ~= "") then
        log(ctx, "get_subdomains request to service failed: " .. err)
        return
    elseif (resp.status_code < 200 or resp.status_code >= 400) then
        log(ctx, "get_subdomains request to service returned with status: " .. resp.status)
        return
    end

    local d = json.decode(resp.body)
    if (d == nil) then
        log(ctx, "failed to decode the JSON get_subdomains response")
        return
    elseif (d.error ~= nil) then
        if (d['error'].message ~= nil and d['error'].message ~= "") then
            log(ctx, "error in the get_subdomains response: " .. d['error'].message)
        end
        return
    elseif (d.assets == nil or #(d.assets) == 0) then
        return
    end

    for _, a in pairs(d.assets) do
        if (a ~= nil and a.name ~= nil and a.name ~= "") then
            new_name(ctx, a.name)
        end
    end
end

function build_url(token)
    return "https://api.detectify.com/rest/v2/assets/" .. token .. "/subdomains/"
end
