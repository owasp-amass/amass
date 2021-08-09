-- Copyright 2020-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "ZoomEye"
type = "api"

function start()
    set_rate_limit(3)
end

function check()
    local c
    local cfg = datasrc_config()
    if cfg ~= nil then
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
    if cfg ~= nil then
        c = cfg.credentials
    end

    if (c == nil or c.username == nil or 
        c.username == "" or c.password == nil or c.password == "") then
        return
    end

    local token = bearer_token(ctx, c.username, c.password)
    if token == "" then
        return
    end

    local resp, err = request(ctx, {
        url="https://api.zoomeye.org/host/search?query=hostname:*." .. domain,
        headers={['Authorization']="JWT " .. token},
    })
    if (err ~= nil and err ~= "") then
        return
    end

    local d = json.decode(resp)
    if (d == nil or d.total == 0 or d.available == 0 or #(d.matches) == 0) then
        return
    end

    for i, host in pairs(d.matches) do
        if (host ~= nil and host['rdns'] ~= nil and host['rdns'] ~= "") then
            new_name(ctx, host['rdns'])
        end
        if (host ~= nil and host['rdns_new'] ~= nil and host['rdns_new'] ~= "") then
            new_name(ctx, host['rdns_new'])
        end
        if (host ~= nil and host['ip'] ~= nil and host['ip'] ~= "") then
            new_addr(ctx, host['ip'], domain)
        end
    end
    -- Just in case
    send_names(ctx, resp)
end

function bearer_token(ctx, username, password)
    local body, err = json.encode({
        username=username, 
        password=password,
    })
    if (err ~= nil and err ~= "") then
        return ""
    end

    resp, err = request(ctx, {
        method="POST",
        data=body,
        url="https://api.zoomeye.org/user/login",
        headers={['Content-Type']="application/json"},
    })
    if (err ~= nil and err ~= "") then
        return ""
    end

    local d = json.decode(resp)
    if (d == nil or d.access_token == nil or d.access_token == "") then
        return ""
    end

    return d.access_token
end
