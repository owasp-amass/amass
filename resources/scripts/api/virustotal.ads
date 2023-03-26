-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local json = require("json")

name = "VirusTotal"
type = "api"

function start()
    set_rate_limit(5)
end

function check()
    local c
    local cfg = datasrc_config()
    if (cfg ~= nil) then
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
    if (cfg ~= nil) then
        c = cfg.credentials
    end

    if (c == nil or c.key == nil or c.key == "") then
        return
    end

    local resp, err = request(ctx, {['url']=build_url(domain, c.key)})
    if (err ~= nil and err ~= "") then
        log(ctx, "vertical request to service failed: " .. err)
        return
    elseif (resp.status_code < 200 or resp.status_code >= 400) then
        log(ctx, "vertical request to service returned with status: " .. resp.status)
        return
    end

    local d = json.decode(resp.body)
    if (d == nil) then
        log(ctx, "failed to decode the JSON response")
        return
    elseif (d.response_code == nil or d.response_code ~= 1) then
        if (d.verbose_msg ~= nil and d.verbose_msg ~= "") then
            log(ctx, "error returned in the response: " .. d.verbose_msg)
        end
        return
    end

    for _, sub in pairs(d.subdomains) do
        if (sub ~= nil and sub ~= "") then
            new_name(ctx, sub)
        end
    end
end

function build_url(domain, key)
    return "https://www.virustotal.com/vtapi/v2/domain/report?domain=" .. domain .. "&apikey=" .. key
end
