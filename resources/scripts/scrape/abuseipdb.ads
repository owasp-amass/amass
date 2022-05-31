-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "AbuseIPDB"
type = "scrape"

function start()
    set_rate_limit(1)
end

function vertical(ctx, domain)
    local _, count = string.gsub(domain, "%.", "")
    if count > 1 then
        return
    end

    local ip = get_ip(ctx, domain)
    if (ip == nil or ip == "") then
        return
    end

    local page, err = request(ctx, {['url']=build_url(ip)})
    if (err ~= nil and err ~= "") then
        log(ctx, "vertical request to service failed: " .. err)
        return
    end

    local pattern = "<h1 style=text\\-align:center>([.a-z0-9-]{1,63})"
    local matches = submatch(page, pattern)
    if (matches == nil or #matches == 0 or not in_scope(ctx, matches[1][2])) then
        return
    end

    pattern = "<li>([.a-z0-9-]{1,256})</li>"
    matches = submatch(page, pattern)
    if (matches == nil or #matches == 0) then
        return
    end

    for _, match in pairs(matches) do
        if (match ~= nil and #match >=2) then
            send_names(ctx, match[2] .. "." .. domain)
        end
    end
end

function build_url(ip)
    return "https://www.abuseipdb.com/whois/" .. ip
end

function get_ip(ctx, domain)
    local page, err = request(ctx, {['url']=ip_url(domain)})
    if (err ~= nil and err ~= "") then
        log(ctx, "get_ip request to service failed: " .. err)
        return nil
    end

    local pattern = "<i\\ class=text\\-primary>(.*)</i>"
    local matches = submatch(page, pattern)
    if (matches == nil or #matches == 0) then
        return nil
    end

    local match = matches[1]
    if (match == nil or #match < 2 or match[2] == "") then
        return nil
    end
    return match[2]
end

function ip_url(domain)
    return "https://www.abuseipdb.com/check/" .. domain
end
