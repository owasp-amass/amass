-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "IPv4Info"
type = "scrape"

function start()
    setratelimit(2)
end

function vertical(ctx, domain)
    local resp
    local cfg = datasrc_config()
    -- Check if the response data is in the graph database
    if (cfg.ttl ~= nil and cfg.ttl > 0) then
        resp = obtain_response(domain, cfg.ttl)
    end

    if (resp == nil or resp == "") then
        local path = getpath(ctx, domain)
        if path == "" then
            return
        end

        local token = gettoken(ctx, domain, path)
        if token == "" then
            return
        end

        local err
        local u = "http://ipv4info.com/subdomains/" .. token .. "/" .. domain .. ".html"
        resp, err = request(ctx, {['url']=u})
        if (err ~= nil and err ~= "") then
            return
        end

        if (cfg.ttl ~= nil and cfg.ttl > 0) then
            cache_response(domain, resp)
        end
    end

    sendnames(ctx, resp)
end

function getpath(ctx, domain)
    local u = "http://ipv4info.com/search/" .. domain
    local page, err = request(ctx, {['url']=u})
    if (err ~= nil and err ~= "") then
        return ""
    end

    local match = find(page, "/ip-address/(.*)/" .. domain)
    if match == nil then
        return ""
    end

    return match[1]
end

function gettoken(ctx, domain, path)
    local u = "http://ipv4info.com" .. path
    local page, err = request(ctx, {['url']=u})
    if (err ~= nil and err ~= "") then
        return ""
    end

    local match = submatch(page, "/dns/(.*?)/" .. domain)
    if (match == nil or #match < 2) then
        return ""
    end

    return match[2]
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
