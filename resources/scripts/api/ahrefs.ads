-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

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

    local resp, err = request(ctx, {['url']=build_url(domain, c.key)})
    if (err ~= nil and err ~= "") then
        log(ctx, "vertical request to service failed: " .. err)
        return
    end

    local j = json.decode(resp)
    if j == nil then
        return
    elseif j.error ~= nil then
        log(ctx, "vertical request to service failed: " .. j.error)
        return
    end

    for _, item in pairs(d.pages) do
        send_names(ctx, item.url)
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
