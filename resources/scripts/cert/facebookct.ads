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

    local page, err = request({
        url=authurl(api.key, api.secret),
        headers={['Content-Type']="application/json"},
    })
    if (err ~= nil and err ~= "") then
        return
    end

    local resp = json.decode(page)
    if (resp == nil or resp.access_token == nil or resp.access_token == "") then
        return
    end

    page, err = request({
        url=queryurl(domain, resp.access_token),
        headers={['Content-Type']="application/json"},
    })
    if (err ~= nil and err ~= "") then
        return
    end

    resp = json.decode(page)
    if (resp == nil or #(resp.data) == 0) then
        return
    end

    for i, r in pairs(resp.data) do
        for j, d in pairs(r.domains) do
            sendnames(ctx, d)
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

    for i, v in pairs(names) do
        newname(ctx, v)
    end
end
