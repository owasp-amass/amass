-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "Censys"
type = "cert"

function start()
    setratelimit(3)
end

function vertical(ctx, domain)
    if api == nil then
        webscrape(ctx, domain)
        return
    end

    apiquery(ctx, domain)
end

function apiquery(ctx, domain)
    local p = 1

    while(true) do
        local body, err = json.encode({
            query="parsed.names: " .. domain, 
            page=p,
            fields={"parsed.names"},
        })
        if (err ~= nil and err ~= "") then
            return
        end

        local page, err = request({
            method="POST",
            data=body,
            url=apiurl(),
            headers={['Content-Type']="application/json"},
            id=api["key"],
            pass=api["secret"],
        })
        if (err ~= nil and err ~= "") then
            return
        end

        local resp = json.decode(page)
        if (resp == nil or resp.status ~= "ok" or #(resp.results) == 0) then
            return
        end

        for i, r in pairs(resp.results) do
            for j, v in pairs(r["parsed.names"]) do
                sendnames(ctx, v)
            end
        end

        if resp["metadata"].page >= resp["metadata"].pages then
            return
        end

        checkratelimit()
        active(ctx)
        p = p + 1
    end
end

function apiurl()
    return "https://www.censys.io/api/v1/search/certificates"
end

function webscrape(ctx, domain)
    local page, err = request({
        url=scrapeurl(domain),
    })
    if (err ~= nil and err ~= '') then
        return
    end

    sendnames(ctx, page)
end

function scrapeurl(domain)
    return "https://www.censys.io/domain/" .. domain .. "/table"
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
