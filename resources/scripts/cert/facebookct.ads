-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "FacebookCT"
type = "cert"

function start()
    setratelimit(20)
end

function vertical(ctx, domain)
    if (api == nil or api.key == "" or api.secret == "") then
        return
    end

    local dec
    local resp
    local cacheurl = queryurl_notoken(domain)
    -- Check if the response data is in the graph database
    if (api.ttl ~= nil and api.ttl > 0) then
        resp = obtain_response(cacheurl, api.ttl)
    end

    if (resp == nil or resp == "") then
        local err

        resp, err = request({
            url=authurl(api.key, api.secret),
            headers={['Content-Type']="application/json"},
        })
        if (err ~= nil and err ~= "") then
            return
        end
    
        dec = json.decode(resp)
        if (dec == nil or dec.access_token == nil or dec.access_token == "") then
            return
        end
    
        resp, err = request({
            url=queryurl(domain, dec.access_token),
            headers={['Content-Type']="application/json"},
        })
        if (err ~= nil and err ~= "") then
            return
        end

        if (api.ttl ~= nil and api.ttl > 0) then
            cache_response(cacheurl, resp)
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

function queryurl_notoken(domain)
    return "https://graph.facebook.com/certificates?fields=domains&query=*." .. domain
end

function sendnames(ctx, content)
    local names = find(content, subdomainre)
    if names == nil then
        return
    end

    for i, v in pairs(names) do
        newname(ctx, v)
    end
end
