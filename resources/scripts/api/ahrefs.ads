-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local url = require("url")
local json = require("json")

name = "Ahrefs"
type = "api"

function start()
    set_rate_limit(1)
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
    elseif (d.error ~= nil and d.error ~= "") then
        log(ctx, "error returned by the service: " .. j.error)
        return
    end

    for _, item in pairs(d.pages) do
        if (item ~= nil and item.url ~= nil and item.url ~= "") then
            send_names(ctx, item.url)
        end
    end
end

function build_url(domain, key)
    local params = {
        ['target']=domain,
        ['token']=key,
        ['from']="ahrefs_rank",
        ['mode']="subdomains",
        ['limit']="1000",
        ['order_by']="ahrefs_rank%3Adesc",
        ['output']="json",
    }

    return "https://apiv2.ahrefs.com/?" .. url.build_query_string(params)
end
