-- Copyright 2017-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "ZETAlytics"
type = "api"

function start()
    set_rate_limit(5)
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
    local resp, err = request(ctx, {
        url=vurl,
        headers={['Content-Type']="application/json"},
    })
    if (err ~= nil and err ~= "") then
        return
    end

    local d = json.decode(resp)
    if (d == nil or #(d.results) == 0) then
        return
    end

    for i, r in pairs(d.results) do
        send_names(ctx, r.qname)
    end
end

function build_url(domain, key)
    return "https://zonecruncher.com/api/v1/subdomains?q=" .. domain .. "&token=" .. key
end
