-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "CommonCrawl"
type = "api"

local urls = {}

function start()
    set_rate_limit(5)
end

function vertical(ctx, domain)
    if (urls == nil or #urls == 0) then
        get_urls(ctx)
    end

    for _, url in pairs(urls) do
        scrape(ctx, {['url']=build_url(url, domain)})
    end
end

function build_url(url, domain)
    return url .. "?url=*." .. domain .. "&output=json&fl=url"
end

function get_urls(ctx)
    local resp, err = request(ctx, {['url']="https://index.commoncrawl.org/collinfo.json"})
    if (err ~= nil and err ~= "") then
        log(ctx, "get_urls request to service failed: " .. err)
        return
    end

    local data = json.decode(resp)
    if (data == nil or #data == 0) then
        return
    end

    for _, u in pairs(data) do
        local url = u['cdx-api']
        if (url ~= nil and url ~= "") then
            table.insert(urls, url)
        end
    end
end
