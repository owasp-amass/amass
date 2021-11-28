-- Copyright 2017-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "BufferOver"
type = "api"

function start()
    set_rate_limit(1)
end

function vertical(ctx, domain)
    scrape(ctx, {url=build_url(domain, "dns")})
    -- The owner requested that this endpoint not be used for now
    -- scrape(ctx, {url=build_url(domain, "tls")})
end

function build_url(domain, sub)
    return "https://" .. sub .. ".bufferover.run/dns?q=." .. domain
end
