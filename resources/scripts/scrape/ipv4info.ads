-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "IPv4Info"
type = "scrape"

function start()
    setratelimit(1)
end

function vertical(ctx, domain)
    local path = getpath(ctx, domain)
    if path == "" then
        return
    end

    local token = gettoken(ctx, domain, path)
    if token == "" then
        return
    end

    local u = "http://ipv4info.com/subdomains/" .. token .. "/" .. domain .. ".html"
    local resp, err = request(ctx, {['url']=u})
    if (err ~= nil and err ~= "") then
        return
    end

    sendnames(ctx, resp)
    -- Attempt to scrape additional pages of subdomain names
    local pagenum = 1
    while(true) do
        local last = resp
        resp = ""

        local page = "page" .. tostring(pagenum)
        local key = domain .. page
       
        resp = nextpage(ctx, domain, last, page)
        if (resp == nil or resp == "") then
            break
        end

        sendnames(ctx, resp)
        pagenum = pagenum + 1
    end
end

function getpath(ctx, domain)
    local u = "http://ipv4info.com/search/" .. domain
    local page, err = request(ctx, {['url']=u})
    if (err ~= nil and err ~= "") then
        return ""
    end

    local match = find(page, "/ip-address/(.*)/" .. domain)
    if (match == nil or #match == 0) then
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
