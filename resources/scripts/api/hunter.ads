-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "Hunter"
type = "api"

function start()
    setratelimit(1)
end

function check()
    local c
    local cfg = datasrc_config()
    if cfg ~= nil then
        c = cfg.credentials
    end

    if (c.apikey ~= nil and c.apikey ~= "") then
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

    if (c.apikey == nil or c.apikey == "") then
        return
    end

    scrape(ctx, {
        ['url']=buildurl(domain, c.apikey),
        headers={['Content-Type']="application/json"},
    })
end

function buildurl(domain, apikey)
    return "https://api.hunter.io/v2/domain-search?domain=" .. domain .. "&api_key=" .. apikey
end
