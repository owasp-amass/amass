-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "ThreatMiner"
type = "api"

function start()
    setratelimit(8)
end

function vertical(ctx, domain)
    local page, err = request(ctx, {
        url=buildurl(domain),
        headers={['Content-Type']="application/json"},
    })
    if (err ~= nil and err ~= "") then
        return
    end

    local resp = json.decode(page)
    if (resp == nil or resp['status_code'] ~= "200" or resp['status_message'] ~= "Results found." or #(resp.results) == 0) then
        return
    end

    for i, sub in pairs(resp.results) do
        sendnames(ctx, sub)
    end
end

function buildurl(domain)
    return "https://api.threatminer.org/v2/domain.php?q=" .. domain .. "&api=True&rt=5"
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
