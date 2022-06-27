-- Copyright 2022 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "PublicWWW"
type = "crawl"

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

    scrape(ctx, {url=build_url(domain, c.key)})
end

function build_url(domain, key)
    return "https://publicwww.com/websites/%22." .. domain .. "%22/?export=csvsnippetsu&key=" .. key
end
