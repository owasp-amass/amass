-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "FacebookCT"
type = "cert"

function start()
    setratelimit(20)
end

function check()
    local c
    local cfg = datasrc_config()
    if cfg ~= nil then
        c = cfg.credentials
    end

    if (c ~= nil and c.key ~= nil and 
        c.secret ~= nil and c.key ~= "" and c.secret ~= "") then
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

    if (c == nil or c.key == nil or 
        c.secret == nil or c.key == "" or c.secret == "") then
        return
    end

    local dec
    local resp
    -- Check if the response data is in the graph database
    if (cfg.ttl ~= nil and cfg.ttl > 0) then
        resp = obtain_response(domain, cfg.ttl)
    end

    if (resp == nil or resp == "") then
        local err

        resp, err = request(ctx, {
            url=authurl(c.key, c.secret),
            headers={['Content-Type']="application/json"},
        })
        if (err ~= nil and err ~= "") then
            return
        end
    
        dec = json.decode(resp)
        if (dec == nil or dec.access_token == nil or dec.access_token == "") then
            return
        end
    
        resp, err = request(ctx, {
            url=queryurl(domain, dec.access_token),
            headers={['Content-Type']="application/json"},
        })
        if (err ~= nil and err ~= "") then
            return
        end

        if (cfg.ttl ~= nil and cfg.ttl > 0) then
            cache_response(domain, resp)
        end
    end

    dec = json.decode(resp)
    if (dec == nil or #(dec.data) == 0) then
        return
    end

    for i, r in pairs(dec.data) do
        for j, name in pairs(r.domains) do
            sendnames(ctx, name)
        end
    end
end

function authurl(id, secret)
    return "https://graph.facebook.com/oauth/access_token?client_id=" .. id .. "&client_secret=" .. secret .. "&grant_type=client_credentials"
end

function queryurl(domain, token)
    return "https://graph.facebook.com/certificates?fields=domains&access_token=" .. token .. "&query=*." .. domain
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
