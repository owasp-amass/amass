-- Copyright © by Jeff Foley 2021-2022. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local json = require("json")

name = "CommonCrawl"
type = "crawl"

local urls = {}

function start()
    set_rate_limit(7)
end

function vertical(ctx, domain)
    if (urls == nil or #urls == 0) then
        get_urls(ctx)
    end

    for _, url in pairs(urls) do
        scrape(ctx, {['url']=url .. domain})
    end
end

function get_urls(ctx)
    local u = "https://index.commoncrawl.org"
    local resp, err = request(ctx, {['url']=u})
    if (err ~= nil and err ~= "") then
        log(ctx, "get_urls request to service failed: " .. err)
        return
    end

    local matches = find(resp, 'CC-MAIN[0-9-]*-index')
    if (matches == nil or #matches == 0) then
        log(ctx, "get_urls failed to extract endpoints")
        return
    end

    for _, endpoint in pairs(matches) do
        table.insert(urls, u .. "/" .. endpoint .. "?output=json&fl=url&url=*.")
    end
end
