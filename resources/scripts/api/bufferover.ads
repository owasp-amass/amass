-- Copyright 2017-2022 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "BufferOver"
type = "api"

function start()
    set_rate_limit(1)
end

function vertical(ctx, domain)
    local c
    local cfg = datasrc_config()
    if cfg ~= nil then
        c = cfg.credentials
    end

    if (c ~= nil and c.key ~= nil and c.key ~= "") then
        scrape(ctx, {
            url=build_url(domain, "tls"),
            headers={['x-api-key']=c["key"]},
        })
    end

    scrape(ctx, {url=build_url(domain, "dns")})
end

function build_url(domain, sub)
    return "https://" .. sub .. ".bufferover.run/dns?q=." .. domain
end
