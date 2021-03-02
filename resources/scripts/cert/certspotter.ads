-- Copyright 2017-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local url = require("url")
local json = require("json")

name = "CertSpotter"
type = "cert"

function start()
    setratelimit(1)
end

function vertical(ctx, domain)
    local vurl = newapiurl(domain)
    local page, err = request(ctx, {['url']=vurl})
    if (err ~= nil and err ~= "") then
        return
    end

    local resp = json.decode(page)
    if (resp == nil or #resp == 0) then
        return
    end

    for i, r in pairs(resp) do
        for i, name in pairs(r['dns_names']) do
            sendnames(ctx, name)
        end
    end
end

function newapiurl(domain)
    local params = {
        ['domain']=domain,
        ['include_subdomains']="true",
        ['match_wildcards']="true",
        expand="dns_names",
    }

    return "https://api.certspotter.com/v1/issuances?" .. url.build_query_string(params)
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
