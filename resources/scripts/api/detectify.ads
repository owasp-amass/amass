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
    if query_asset(ctx, domain, key) then
        return
    end

    -- Add domain to monitoring assets
    local resp, err = request(ctx, {
        url="https://api.detectify.com/rest/v2/domains/",
        method="POST",
        data=json.encode({['name']=domain}),
        headers={['X-Detectify-Key']=c.key},
    })
    if (err ~= nil and err ~= "") then
        return
    end

    -- Wait a bit for Detectify to enumerate subdomains
    for i=1,25 do check_rate_limit() end
    query_asset(ctx, domain, key)
end

function query_asset(ctx, domain, key)
    local resp, err = request(ctx, {
        url="https://api.detectify.com/rest/v2/domains/",
        headers={['X-Detectify-Key']=key},
    })
    if (err ~= nil and err ~= "") then
        return false
    end

    local j = json.decode(resp)
    if (j ~= nil and #j > 0) then
        for _, a in pairs(j) do
            if a.name == domain then
                query_subdomains(ctx, a.token, key)
                return true
            end
        end
    end
    return false
end

function query_subdomains(ctx, token, key)
    local resp, err = request(ctx, {
        url=build_url(token),
        headers={['X-Detectify-Key']=key},
    })
    if (err ~= nil and err ~= "") then
        return
    end

    local j = json.decode(resp)
    if (j == nil or #j == 0) then
        return
    end

    for _, s in pairs(j) do
        new_name(ctx, s.name)
    end
end

function build_url(token)
    return "https://api.detectify.com/rest/v2/domains/" .. token .. "/subdomains/"
end
