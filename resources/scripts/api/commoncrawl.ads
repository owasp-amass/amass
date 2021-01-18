-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "CommonCrawl"
type = "api"

local urls = {}

function start()
    setratelimit(1)
end

function vertical(ctx, domain)
    -- Check that the index URLs have been obtained
    if (urls == nil or #urls == 0) then
        urls = indexurls(ctx)
        if (urls == nil or #urls == 0) then
            return
        end

        checkratelimit()
    end

    for i, url in pairs(urls) do
        scrape(ctx, {
            ['url']=buildurl(url, domain),
            headers={['Content-Type']="application/json"},
        })

        checkratelimit()
    end
end

function buildurl(url, domain)
    return url .. "?url=*." .. domain .. "&output=json&fl=url"
end

function indexurls(ctx)
    local resp
    local cfg = datasrc_config()
    local iurl = "https://index.commoncrawl.org/collinfo.json"
    -- Check if the response data is in the graph database
    if (cfg.ttl ~= nil and cfg.ttl > 0) then
        resp = obtain_response(iurl, cfg.ttl)
    end

    if (resp == nil or resp == "") then
        local err

        resp, err = request({
            url=iurl,
            headers={['Content-Type']="application/json"},
        })
        if (err ~= nil and err ~= "") then
            log(ctx, err .. ": " .. resp)
            return nil
        end

        if (cfg.ttl ~= nil and cfg.ttl > 0) then
            cache_response(iurl, resp)
        end
    end

    local data = json.decode(resp)
    if (data == nil or #data == 0) then
        return nil
    end

    local urls = {}
    for i, u in pairs(data) do
        local url = u["cdx-api"]
        if (url ~= nil and url ~= "") then
            table.insert(urls, url)
        end
    end

    return urls
end
