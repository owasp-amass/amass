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

    local vurl = build_url(domain, c.key)
    local resp, err = request(ctx, {['url']=vurl})
    if (err ~= nil and err ~= "") then
        log(ctx, "vertical request to service failed: " .. err)
        return
    end

    local d = json.decode(resp)
    if d == nil or d.response_code ~= 1 then
        log(ctx, name .. ": " .. vurl .. ": HTTP status " .. d.response_code .. ": " .. d.verbose_msg)
        return
    end

    if d.subdomains == nil then
        return
    end

    for _, sub in pairs(d.subdomains) do
        new_name(ctx, sub)
    end
end

function build_url(domain, key)
    return "https://www.virustotal.com/vtapi/v2/domain/report?domain=" .. domain .. "&apikey=" .. key
end
