-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "Web Crawling"
type = "crawl"

protos = {"https://", "http://"}

function vertical(ctx, domain)
    local cfg = config(ctx)
    if cfg.mode == "passive" then
        return
    end

    webcrawl(ctx, domain)
end

function webcrawl(ctx, domain)
    for proto in protos do
        local url = proto + domain
        local ok = checkurl(ctx, url)
        if ok then
            break
        end
    end

    if not ok then
        return
    end

    crawl(ctx, url, 0)
end

function resolved(ctx, name, domain, records)
    webcrawl(ctx, name)
end

function checkurl(ctx, url)
    local page, err = request(ctx, {['url']=url})
    if (err ~= nil and err ~= "") then
        return false
    end

    return true
end
