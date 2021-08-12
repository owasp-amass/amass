-- Copyright 2020-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "VirusTotal"
type = "api"

function start()
    set_rate_limit(10)
end

function check()
    local c
    local cfg = datasrc_config()
    if cfg ~= nil then
        c = cfg.credentials
    end

    if (c ~= nil and c.key ~= nil and c.key ~= "") then
        return true
    end
    return false
end

function vertical(ctx, domain)
    local c
    local cfg = datasrc_config()
    if cfg ~= nil then
        c = cfg.credentials
    end

    if (c == nil or c.key == nil or c.key == "") then
        return
    end

    local vurl = "https://www.virustotal.com/vtapi/v2/domain/report?apikey=" .. c.key .. "&domain=" .. domain

    local resp, err = request(ctx, {url=vurl})
    if (err ~= nil and err ~= "") then
        return
    end

    local d = json.decode(resp)
    if d['response_code'] ~= 1 then
        log(ctx, name .. ": " .. vurl .. ": Response code " .. d['response_code'] .. ": " .. d['verbose_msg'])
        return
    end

    if d.subdomains == nil then
        return
    end

    for i, sub in pairs(d.subdomains) do
        new_name(ctx, sub)
    end
end
