-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local json = require("json")

name = "FacebookCT"
type = "cert"
api_version = "v11.0"

function start()
    set_rate_limit(5)
end

function check()
    local c
    local cfg = datasrc_config()
    if (cfg ~= nil) then
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
        resp, err = request(ctx, {['url']=nxt})
        if (err ~= nil and err ~= "") then
            log(ctx, "vertical request to service failed: " .. err)
            return
        elseif (resp.status_code < 200 or resp.status_code >= 400) then
            log(ctx, "vertical request to service returned with status code: " .. resp.status)
            return
        end

        d = json.decode(resp.body)
        if (d == nil) then
            log(ctx, "failed to decode the JSON response")
            return
        elseif (d.data == nil or #(d.data) == 0) then
            return
        end

        for _, r in pairs(d.data) do
            for _, name in pairs(r.domains) do
                new_name(ctx, name)
            end
        end

        nxt = ""
        if (d.paging ~= nil and d.paging.next ~= nil and d.paging.next ~= "") then
            nxt = d.paging.next
        end
    end
end

function get_token(ctx)
    local c
    local cfg = datasrc_config()
    if (cfg ~= nil) then
        c = cfg.credentials
    end

    if (c == nil or c.key == nil or 
        c.secret == nil or c.key == "" or c.secret == "") then
        return ""
    end

    local authurl = "https://graph.facebook.com/oauth/access_token"
    authurl = authurl .. "?client_id=" .. c.key .. "&client_secret=" .. c.secret .. "&grant_type=client_credentials"

    local resp, err = request(ctx, {['url']=authurl})
    if (err ~= nil and err ~= "") then
        log(ctx, "auth request to service failed: " .. err)
        return ""
    elseif (resp.status_code < 200 or resp.status_code >= 400) then
        log(ctx, "auth request to service returned with status code: " .. resp.status)
        return ""
    end
    
    local d = json.decode(resp.body)
    if (d == nil) then
        log(ctx, "failed to decode the auth JSON response")
        return ""
    elseif (d.access_token == nil or d.access_token == "") then
        return ""
    end

    return d.access_token
end

function query_url(domain, token)
    if token == "" then
        return ""
    end

    local u = "https://graph.facebook.com/" .. api_version
    return u .. "/certificates?fields=domains&access_token=" .. token .. "&query=*." .. domain
end
