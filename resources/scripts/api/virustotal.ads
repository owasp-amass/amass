-- Copyright 2017-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "VirusTotal"
type = "api"

function start()
    setratelimit(10)
end

function vertical(ctx, domain)
    local c
    local cfg = datasrc_config()
    if cfg ~= nil then
        c = cfg.credentials
    end

    local haskey = true
    if (c == nil or c.key == nil or c.key == "") then
        haskey = false
    end

    local vurl = buildurl(domain)
    if haskey then
        vurl = apiurl(domain, c.key)
    end

    local resp, err = request(ctx, {
        url=vurl,
        headers={['Content-Type']="application/json"},
    })
    if (err ~= nil and err ~= "") then
        return
    end

    local d = json.decode(resp)
    if haskey then
        if d['response_code'] ~= 1 then
            log(ctx, name .. ": " .. vurl .. ": Response code " .. d['response_code'] .. ": " .. d['verbose_msg'])
            return
        end

        for i, sub in pairs(d.subdomains) do
            sendnames(ctx, sub)
        end
    else
        for i, data in pairs(d.data) do
            if data.type == "domain" then
                sendnames(ctx, data.id)
            end
        end
    end
end

function buildurl(domain)
    return "https://www.virustotal.com/ui/domains/" .. domain .. "/subdomains?limit=40"
end

function apiurl(domain, key)
    return "https://www.virustotal.com/vtapi/v2/domain/report?apikey=" .. key .. "&domain=" .. domain
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
