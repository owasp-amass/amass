-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "NetCraft"
type = "scrape"

function start()
    setratelimit(1)
end

function vertical(ctx, domain)
    scrape(ctx, {['url']="https://searchdns.netcraft.com/?restriction=site+ends+with&host=" .. domain})
end
