-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "BuiltWith"
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

    scrape(ctx, {url=first_url(domain, c.key)})
    scrape(ctx, {url=second_url(domain, c.key)})
end

function first_url(domain, key)
    return "https://api.builtwith.com/v19/api.json?LOOKUP=" .. domain .. "&KEY=" .. key
end

function second_url(domain, key)
    return "https://api.builtwith.com/rv1/api.json?LOOKUP=" .. domain .. "&KEY=" .. key
end
