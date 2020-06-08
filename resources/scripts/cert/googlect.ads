-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "GoogleCT"
type = "cert"

function start()
    setratelimit(1)
end

function vertical(ctx, domain)
    local token = ""
    local hdrs={
        Connection="close",
        Referer="https://transparencyreport.google.com/https/certificates",
    }

    while(true) do
        local page, err = request({
            url=buildurl(domain, token),
            headers=hdrs,
        })
        if (err ~= nil and err ~= "") then
            break
        end

        sendnames(ctx, page)

        token = gettoken(page)
        if token == "" then
            break
        end

        checkratelimit()
        active(ctx)
    end
end

function buildurl(domain, token)
    local url = "https://www.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch"

    if token ~= "" then
        url = url .. "/page"
    end

    url = url .. "?domain=" .. domain
    url = url .. "&include_expired=true"
    url = url .. "&include_subdomains=true"

    if token ~= "" then
        url = url .. "&p=" .. token
    end

    return url
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

function gettoken(content)
    local pattern = "\\[(null|\"[a-zA-Z0-9]+\"),\"([a-zA-Z0-9]+)\",null,([0-9]+),([0-9]+)\\]"
    local match = submatch(content, pattern)

    if (match ~= nil and #match == 5 and (match[4] < match[5])) then
        return match[3]
    end

    return ""
end
