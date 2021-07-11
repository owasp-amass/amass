-- Copyright 2017-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "FacebookCT"
type = "cert"
api_version = "v11.0"

function start()
    setratelimit(5)
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
    local next = queryurl(domain, gettoken(ctx))

    while next ~= "" do
        resp, err = request(ctx, {
            url=next,
            headers={['Content-Type']="application/json"},
        })
        if (err ~= nil and err ~= "") then
            return
        end

        dec = json.decode(resp)
        if (dec == nil or dec.data == nil or #(dec.data) == 0) then
            return
        end

        for _, r in pairs(dec.data) do
            for _, name in pairs(r.domains) do
                newname(ctx, name)
            end
        end

        next = ""
        if (dec.paging ~= nil and dec.paging.next ~= nil and dec.paging.next ~= "") then
            next = dec.paging.next
        end
    end
end

function gettoken(ctx)
    local c
    local cfg = datasrc_config()
    if cfg ~= nil then
        c = cfg.credentials
    end

    if (c == nil or c.key == nil or 
        c.secret == nil or c.key == "" or c.secret == "") then
        return ""
    end

    local authurl = "https://graph.facebook.com/oauth/access_token"
    authurl = authurl .. "?client_id=" .. c.key .. "&client_secret=" .. c.secret .. "&grant_type=client_credentials"

    local resp, err = request(ctx, {
        url=authurl,
        headers={['Content-Type']="application/json"},
    })
    if (err ~= nil and err ~= "") then
        return ""
    end
    
    local dec = json.decode(resp)
    if (dec == nil or dec.access_token == nil or dec.access_token == "") then
        return ""
    end

    return dec.access_token
end

function queryurl(domain, token)
    if token == "" then
        return ""
    end

    local u = "https://graph.facebook.com/" .. api_version
    return u .. "/certificates?fields=domains&access_token=" .. token .. "&query=*." .. domain
end
