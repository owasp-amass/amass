-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "SecurityTrails"
type = "api"

function start()
    setratelimit(1)
end

function vertical(ctx, domain)
    if (api == nil or api.key == "") then
        return
    end

    local page, err = request({
        url=verturl(domain),
        headers={
            APIKEY=api.key,
            ['Content-Type']="application/json",
        },
    })
    if (err ~= nil and err ~= "") then
        return
    end

    local j = json.decode(page)
    if (j == nil or #(j.subdomains) == 0) then
        return
    end

    for i, sub in pairs(j.subdomains) do
        sendnames(ctx, sub .. "." .. domain)
    end
end

function verturl(domain)
    return "https://api.securitytrails.com/v1/domain/" .. domain .. "/subdomains"
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

function horizontal(ctx, domain)
    if (api == nil or api.key == "") then
        return
    end

    local page, err = request({
        url=horizonurl(domain),
        headers={
            APIKEY=api.key,
            ['Content-Type']="application/json",
        },
    })
    if (err ~= nil and err ~= "") then
        return
    end

    local j = json.decode(page)
    if (j == nil or #(j.records) == 0) then
        return
    end

    assoc = {}
    for i, r in pairs(j.records) do
        if r.hostname ~= "" then
            table.insert(assoc, r.hostname)
        end
    end

    for i, a in pairs(assoc) do
        associated(ctx, domain, a)
    end
end

function horizonurl(domain)
    return "https://api.securitytrails.com/v1/domain/" .. domain .. "/associated"
end
