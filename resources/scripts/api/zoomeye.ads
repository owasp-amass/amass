-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local json = require("json")

name = "ZoomEye"
type = "api"

function start()
    set_rate_limit(3)
end

function check()
    local c
    local cfg = datasrc_config()
    if (cfg ~= nil) then
        c = cfg.credentials
    end

    if (c ~= nil and c.username ~= nil and 
        c.password ~= nil and c.username ~= "" and c.password ~= "") then
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

    if (c == nil or c.username == nil or 
        c.username == "" or c.password == nil or c.password == "") then
        return
    end

    local token = bearer_token(ctx, c.username, c.password)
    if (token == "") then
        return
    end

    local resp, err = request(ctx, {
        ['url']="https://api.zoomeye.org/host/search?query=hostname:*." .. domain,
        ['header']={['Authorization']="JWT " .. token},
    })
    if (err ~= nil and err ~= "") then
        log(ctx, "vertical request to service failed: " .. err)
        return
    elseif (resp.status_code < 200 or resp.status_code >= 400) then
        log(ctx, "vertical request to service returned with status: " .. resp.status)
        return
    end

    local d = json.decode(resp.body)
    if (d == nil) then
        log(ctx, "failed to decode the JSON response")
        return
    elseif (d.total == nil or d.total == 0 or d.available == nil or d.available == 0) then
        return
    end

    for i, host in pairs(d.matches) do
        if (host ~= nil) then
            if (host['rdns'] ~= nil and host['rdns'] ~= "") then
                new_name(ctx, host['rdns'])
            end
            if (host['rdns_new'] ~= nil and host['rdns_new'] ~= "") then
                new_name(ctx, host['rdns_new'])
            end
            if (host['ip'] ~= nil and host['ip'] ~= "") then
                new_addr(ctx, host['ip'], domain)
            end
        end
    end
    -- Just in case
    send_names(ctx, resp.body)
end

function bearer_token(ctx, username, password)
    local body, err = json.encode({
        ['username']=username, 
        ['password']=password,
    })
    if (err ~= nil and err ~= "") then
        return ""
    end

    local resp, err = request(ctx, {
        ['url']="https://api.zoomeye.org/user/login",
        ['method']="POST",
        ['header']={['Content-Type']="application/json"},
        ['body']=body,
    })
    if (err ~= nil and err ~= "") then
        log(ctx, "bearer_token request to service failed: " .. err)
        return
    elseif (resp.status_code < 200 or resp.status_code >= 400) then
        log(ctx, "bearer_token request to service returned with status: " .. resp.status)
        return
    end

    local d = json.decode(resp.body)
    if (d == nil) then
        log(ctx, "failed to decode the bearer_token response")
        return ""
    elseif (d.access_token == nil or d.access_token == "") then
        return ""
    end

    return d.access_token
end
