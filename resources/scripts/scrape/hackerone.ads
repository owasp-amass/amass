-- Copyright 2017-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "HackerOne"
type = "scrape"

function start()
    set_rate_limit(1)
end

function vertical(ctx, domain)
    scrape(ctx, {['url']=build_url(domain)})
end

function build_url(domain)
    return "http://h1.nobbd.de/search.php?q=." .. domain
end
