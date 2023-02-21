-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local url = require("url")
local json = require("json")

name = "CommonCrawl"
type = "crawl"

local endpoints = {}
local max_collections = 6

function start()
    set_rate_limit(1)
end

function vertical(ctx, domain)
    if (endpoints == nil or #endpoints == 0) then
        get_endpoints(ctx)
    end

    local params = {
        ['output']="json",
        ['fl']="url",
        ['url']="*." .. domain,
    }
    local query_string = "?" .. url.build_query_string(params)

    for _, endpoint in pairs(endpoints) do
        scrape(ctx, {['url']=endpoint .. query_string})
    end
end

function get_endpoints(ctx)
    local resp, err = request(ctx, {['url']="https://index.commoncrawl.org/collinfo.json"})
    if (err ~= nil and err ~= "") then
        log(ctx, "vertical request to service failed: " .. err)
        return
    elseif (resp.status_code < 200 or resp.status_code >= 400) then
        log(ctx, "vertical request to service returned with status code: " .. resp.status)
        return
    end
    local body = "{\"collections\":" .. resp.body .. "}"

    local d = json.decode(body)
    if (d == nil) then
        log(ctx, "failed to decode the JSON response")
        return
    elseif (d.collections == nil or #(d.collections) == 0) then
        return
    end

    local count = 0
    for _, r in pairs(d.collections) do
        if (count >= max_collections) then
            break
        end

        if (r['cdx-api'] ~= nil and r['cdx-api'] ~= "") then
            count = count + 1
            table.insert(endpoints, r['cdx-api'])
        end
    end
end
