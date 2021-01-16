-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "SiteDossier"
type = "scrape"

function start()
    setratelimit(1)
end

function vertical(ctx, domain)
    for i=1,10000,100 do
        local ok = scrape(ctx, {url=buildurl(domain, i)})
        if not ok then
            break
        end

        checkratelimit()
    end
end

function buildurl(domain, pagenum)
    return "http://www.sitedossier.com/parentdomain/" .. domain .. "/" .. pagenum
end
