-- Copyright 2017-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")
local url = require("url")

name = "FacebookCT"
type = "cert"
api_version = "v11.0"

function start()
    set_rate_limit(5)
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
    local nxt = query_url(domain, get_token(ctx))

    while nxt ~= "" do
        resp, err = request(ctx, {url=nxt})
        if (err ~= nil and err ~= "") then
            return
        end

        d = json.decode(resp)
        if (d == nil or d.data == nil or #d.data == 0) then
            return
        end

        for _, r in pairs(d.data) do
            for _, name in pairs(r.domains) do
                new_name(ctx, name)
            end
        end

        nxt = ""
        if (d.paging ~= nil and d['paging'].next ~= nil and d['paging'].next ~= "") then
            nxt = d['paging'].next
        end
    end
end

function get_token(ctx)
    local c
    local cfg = datasrc_config()
    if cfg ~= nil then
        c = cfg.credentials
    end

    if (c == nil or c.key == nil or 
        c.secret == nil or c.key == "" or c.secret == "") then
        return ""
    end

    local resp, err = request(ctx, {url=auth_url(domain, c.key, c.secret)})
    if (err ~= nil and err ~= "") then
        return ""
    end
    
    local dec = json.decode(resp)
    if (dec == nil or dec.access_token == nil or dec.access_token == "") then
        return ""
    end

    return dec.access_token
end

function auth_url(domain, key, secret)
    local params = {
        ['client_id']=key,
        ['client_secret']=secret,
        ['grant_type']="client_credentials",
    }

    return "https://graph.facebook.com/oauth/access_token?" .. url.build_query_string(params)
end

function query_url(domain, token)
    if token == "" then
        return ""
    end

    local params = {
        ['access_token']=token,
        ['query']="*." .. domain,
        ['fields']="domains",
    }
    return "https://graph.facebook.com/" .. api_version .. "/certificates?" .. url.build_query_string(params)
end
