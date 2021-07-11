-- Copyright 2017-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "BufferOver"
type = "api"

function start()
    setratelimit(1)
end

function vertical(ctx, domain)
    scrape(ctx, {url=buildurl(domain, "dns")})
    scrape(ctx, {url=buildurl(domain, "tls")})
end

function buildurl(domain, sub)
    return "https://" .. sub .. ".bufferover.run/dns?q=." .. domain
end
