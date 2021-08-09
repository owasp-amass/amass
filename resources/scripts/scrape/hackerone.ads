-- Copyright 2017-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "HackerOne"
type = "scrape"

function start()
    set_rate_limit(1)
end

function vertical(ctx, domain)
    local vurl = "http://h1.nobbd.de/search.php?q=" .. domain

    scrape(ctx, {['url']=vurl})
end
