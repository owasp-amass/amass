-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "IPv4Info"
type = "scrape"

function start()
    setratelimit(1)
end

function vertical(ctx, domain)
    local resp
    local cfg = datasrc_config()
    -- Check if the response data is in the graph database
    if (cfg.ttl ~= nil and cfg.ttl > 0) then
        resp = obtain_response(domain, cfg.ttl)
    end

    if (resp == nil or resp == "") then
        local token = gettoken(ctx, domain)
        if token == "" then
            return
        end

        local err
        local u = "http://ipv4info.com/subdomains/" .. token .. "/" .. domain .. ".html"
        checkratelimit()
        resp, err = request(ctx, {['url']=u})
        if (err ~= nil and err ~= "") then
            return
        end

        if (cfg.ttl ~= nil and cfg.ttl > 0) then
            cache_response(domain, resp)
        end
    end

    sendnames(ctx, resp)
    -- Attempt to scrape additional pages of subdomain names
    local pagenum = 1
    while(true) do
        local last = resp
        resp = ""

        local page = "page" .. tostring(pagenum)
        local key = domain .. page
        if (cfg.ttl ~= nil and cfg.ttl > 0) then
            resp = obtain_response(key, cfg.ttl)
        end
    
        if (resp == nil or resp == "") then
            checkratelimit()
            resp = nextpage(ctx, domain, last, page)
            if (resp == nil or resp == "") then
                break
            end

            if (cfg.ttl ~= nil and cfg.ttl > 0) then
                cache_response(key, resp)
            end
        end

        if (resp ~= nil and resp ~= "") then
            sendnames(ctx, resp)
        end

        pagenum = pagenum + 1
    end
end

function gettoken(ctx, domain)
    local u = "http://ipv4info.com/search/NF/" .. domain
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

function nextpage(ctx, domain, resp, page)
    local match = find(resp, "/subdomains/(.*)/" .. page .. "/" .. domain .. ".html")
    if (match == nil or #match == 0) then
        return ""
    end

    local u = "http://ipv4info.com" .. match[1]
    local page, err = request(ctx, {['url']=u})
    if (err ~= nil and err ~= "") then
        return ""
    end

    return page
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
