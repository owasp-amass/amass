-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "ZoomEye"
type = "api"

function start()
    setratelimit(3)
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

    local token = bearer_token(c.username, c.password)
    if token == "" then
        return
    end

    local resp
    local vurl = buildurl(domain)
    -- Check if the response data is in the graph database
    if (cfg.ttl ~= nil and cfg.ttl > 0) then
        resp = obtain_response(domain, cfg.ttl)
    end

    if (resp == nil or resp == "") then
        local err

        resp, err = request({
            url=vurl,
            headers={
                ['Content-Type']="application/json",
                ['Authorization']="JWT " .. token,
            },
        })
        if (err ~= nil and err ~= "") then
            log(ctx, err .. ": " .. resp)
            return
        end

        if (cfg.ttl ~= nil and cfg.ttl > 0) then
            cache_response(domain, resp)
        end
    end

    local d = json.decode(resp)
    if (d == nil or d.total == 0 or d.available == 0 or #(d.matches) == 0) then
        return
    end

    for i, host in pairs(d.matches) do
        sendnames(ctx, host.rdns)
        sendnames(ctx, host['rdns_new'])
        newaddr(ctx, domain, host.ip)
    end
    -- Just in case
    sendnames(ctx, resp)
end

function buildurl(domain)
    return "https://api.zoomeye.org/host/search?query=hostname:*." .. domain
end

function bearer_token(username, password)
    local body, err = json.encode({
        username=username, 
        password=password,
    })
    if (err ~= nil and err ~= "") then
        return ""
    end

    resp, err = request({
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

function sendnames(ctx, content)
    local names = find(content, subdomainre)
    if names == nil then
        return
    end

    local found = {}
    for i, v in pairs(names) do
        if found[v] == nil then
            newname(ctx, v)
            found[v] = true
        end
    end
end
