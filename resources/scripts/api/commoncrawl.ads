-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "CommonCrawl"
type = "api"

local urls = {}

function start()
    setratelimit(2)
end

function vertical(ctx, domain)
    urls = indexurls(ctx)
    if (urls == nil or #urls == 0) then
        return
    end

    for _, url in pairs(urls) do
        scrape(ctx, {
            ['url']=buildurl(url, domain),
            headers={['Content-Type']="application/json"},
        })
    end
end

function buildurl(url, domain)
    return url .. "?url=*." .. domain .. "&output=json&fl=url"
end

function indexurls(ctx)
    local resp, err = request(ctx, {
        url="https://index.commoncrawl.org/collinfo.json",
        headers={['Content-Type']="application/json"},
    })
    if (err ~= nil and err ~= "") then
        return nil
    end

    local data = json.decode(resp)
    if (data == nil or #data == 0) then
        return nil
    end

    local urls = {}
    for _, u in pairs(data) do
        local url = u["cdx-api"]
        if (url ~= nil and url ~= "") then
            table.insert(urls, url)
        end
    end

    return urls
end
