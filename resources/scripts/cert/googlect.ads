-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local url = require("url")

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
            ['url']=buildurl(domain, token),
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
    end
end

function buildurl(domain, token)
    local base = "https://www.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch"
    if token ~= "" then
        base = base .. "/page"
    end

    local params = {
        ['domain']=domain,
        ['include_expired']="true",
        ['include_subdomains']="true",
    }
    if token ~= "" then
        params['p'] = token
    end

    return base .. "?" .. url.build_query_string(params)
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

function gettoken(content)
    local pattern = "\\[(null|\"[a-zA-Z0-9]+\"),\"([a-zA-Z0-9]+)\",null,([0-9]+),([0-9]+)\\]"
    local match = submatch(content, pattern)

    if (match ~= nil and #match == 5 and (match[4] < match[5])) then
        return match[3]
    end

    return ""
end
