-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "Gists"
type = "scrape"

function start()
    setratelimit(1)
end

function vertical(ctx, domain)
    local gistre = "https://gist\\.github\\.com/[a-zA-Z0-9\\-]{1,39}/[a-z0-9]{32}"
    for i=1,10 do
        local resp, err = request(ctx, {url=buildurl(domain, i)})
        if (err ~= nil and err ~= "") then
            break
        end

        local gists = find(resp, gistre)
        if (gists == nil or #gists == 0) then
            break
        end

        for i, url in pairs(gists) do
            scrape(ctx, {['url']=url})
        end
        checkratelimit()
    end
end

function buildurl(domain, pagenum)
    return "https://gist.github.com/search?ref=searchresults&q=" .. domain .. "&p=" .. pagenum
end
