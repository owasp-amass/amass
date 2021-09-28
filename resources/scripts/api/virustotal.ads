-- Copyright 2020-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "VirusTotal"
type = "api"

function start()
    set_rate_limit(10)
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

    local vurl = "https://www.virustotal.com/ui/domains/" .. domain .. "/subdomains?limit=40"
    if haskey then
        vurl = "https://www.virustotal.com/vtapi/v2/domain/report?apikey=" .. c.key .. "&domain=" .. domain
    end

    local resp, err = request(ctx, {['url']=vurl})
    if (err ~= nil and err ~= "") then
        log(ctx, "vertical request to service failed: " .. err)
        return
    end

    local d = json.decode(resp)
    if haskey then
        if d['response_code'] ~= 1 then
            log(ctx, vurl .. ": Response code " .. d['response_code'] .. ": " .. d['verbose_msg'])
            return
        end

        if d.subdomains == nil then
            return
        end

        for i, sub in pairs(d.subdomains) do
            new_name(ctx, sub)
        end
    else
        if d.data == nil then
            return
        end

        for i, data in pairs(d.data) do
            if data.type == "domain" then
                new_name(ctx, data.id)
            end
        end
    end
end
