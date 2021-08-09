-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "AbuseIPDB"
type = "scrape"

function start()
    set_rate_limit(1)
end

function vertical(ctx, domain)
    local ip = get_ip(ctx, domain)
    if (ip == nil or ip == "") then
        return
    end

    local page, err = request(ctx, {url=build_url(ip)})
    if (err ~= nil and err ~= "") then
        return
    end

    local pattern = "<li>([.a-z0-9-]{1,70})</li>"
    local matches = submatch(page, pattern)
    if (matches == nil or #matches == 0) then
        return
    end

    for i, match in pairs(matches) do
        if (match ~= nil and #match >=2) then
            local name = match[2] .. "." .. domain
            send_names(ctx, name)
        end
    end
end

function build_url(ip)
    return "https://www.abuseipdb.com/whois/" .. ip
end

function get_ip(ctx, domain)
    local page, err = request(ctx, {url=ip_url(domain)})
    if (err ~= nil and err ~= "") then
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

function send_names(ctx, content)
    local names = find(content, subdomain_regex)
    if (names == nil) then
        return
    end

    local found = {}
    for i, v in pairs(names) do
        if (found[v] == nil) then
            new_name(ctx, v)
            found[v] = true
        end
    end
end
