-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "BufferOver"
type = "api"

function start()
    setratelimit(1)
end

function vertical(ctx, domain)
    scrape(ctx, buildurl(domain))
end

function buildurl(domain)
    return "https://dns.bufferover.run/dns?q=." .. domain
end
