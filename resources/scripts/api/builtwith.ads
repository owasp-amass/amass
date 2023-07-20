-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

name = "BuiltWith"
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

    scrape(ctx, {['url']=build_url(domain, "v19", c.key)})
    scrape(ctx, {['url']=build_url(domain, "rv1", c.key)})
end

function build_url(domain, api, key)
    return "https://api.builtwith.com/" .. api .. "/api.json?LOOKUP=" .. domain .. "&KEY=" .. key
end
