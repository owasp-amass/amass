-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "AbuseIPDB"
type = "scrape"

function start()
    setratelimit(1)
end

function vertical(ctx, domain)
    local ip = getip(ctx, domain)
    if (ip == nil or ip == "") then
        return
    end

    local page, err = request(ctx, {url=buildurl(ip)})
    if (err ~= nil and err ~= "") then
        return
    end

    local subre = "<li>([\\.a-z0-9-]{1,70})</li>"
    local matches = submatch(page, subre)
    if (matches == nil or #matches == 0) then
        return
    end

    for i, sub in pairs(matches) do
        local v = sub .. "." .. domain
        sendnames(ctx, v)
    end
end

function buildurl(ip)
    return "https://www.abuseipdb.com/whois/" .. ip
end

function getip(ctx, domain)
    local page, err = request(ctx, {url=ipurl(domain)})
    if (err ~= nil and err ~= "") then
        return nil
    end

    local ipre = "<i\\ class=text\\-primary>(.*)</i>"
    local matches = submatch(page, ipre)
    if (matches == nil or #matches == 0) then
        return nil
    end

    return matches[1]
end

function ipurl(domain)
    return "https://www.abuseipdb.com/check/" .. domain
end

function sendnames(ctx, content)
    local names = find(content, subdomainre)
    if (names == nil) then
        return
    end

    local found = {}
    for i, v in pairs(names) do
        if (found[v] == nil) then
            newname(ctx, v)
            found[v] = true
        end
    end
end
