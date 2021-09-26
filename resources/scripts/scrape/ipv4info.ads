-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "IPv4Info"
type = "scrape"

function start()
    set_rate_limit(2)
end

function vertical(ctx, domain)
    local path = get_path(ctx, domain)
    if path == "" then
        return
    end

    local token = get_token(ctx, domain, path)
    if token == "" then
        return
    end

    local u = "http://ipv4info.com/subdomains/" .. token .. "/" .. domain .. ".html"
    local resp, err = request(ctx, {['url']=u})
    if (err ~= nil and err ~= "") then
        log(ctx, "vertical request to service failed: " .. err)
        return
    end

    send_names(ctx, resp)
    -- Attempt to scrape additional pages of subdomain names
    local pagenum = 1
    while(true) do
        local last = resp
        resp = ""

        local page = "page" .. tostring(pagenum)
        local key = domain .. page
       
        resp = next_page(ctx, domain, last, page)
        if (resp == nil or resp == "") then
            break
        end

        send_names(ctx, resp)
        pagenum = pagenum + 1
    end
end

function get_path(ctx, domain)
    local u = "http://ipv4info.com/search/" .. domain
    local page, err = request(ctx, {['url']=u})
    if (err ~= nil and err ~= "") then
        log(ctx, "get_path request to service failed: " .. err)
        return ""
    end

    local match = find(page, "/ip-address/(.*)/" .. domain)
    if (match == nil or #match == 0) then
        return ""
    end

    return match[1]
end

function get_token(ctx, domain, path)
    local u = "http://ipv4info.com" .. path
    local page, err = request(ctx, {['url']=u})
    if (err ~= nil and err ~= "") then
        log(ctx, "get_token request to service failed: " .. err)
        return ""
    end

    local matches = submatch(page, "/dns/(.*?)/" .. domain)
    if (matches == nil or #matches == 0) then
        return ""
    end

    local match = matches[1]
    if (match == nil or #match < 2) then
        return ""
    end

    return match[2]
end

function next_page(ctx, domain, resp, page)
    local match = find(resp, "/subdomains/(.*)/" .. page .. "/" .. domain .. ".html")
    if (match == nil or #match == 0) then
        return ""
    end

    local u = "http://ipv4info.com" .. match[1]
    local page, err = request(ctx, {['url']=u})
    if (err ~= nil and err ~= "") then
        log(ctx, "next_page request to service failed: " .. err)
        return ""
    end

    return page
end
