-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local json = require("json")

name = "GitHub"
type = "api"

local rate_error_url = "https://docs.github.com/rest/overview/resources-in-the-rest-api#rate-limiting"

function start()
    set_rate_limit(7)
end

function check()
    local c
    local cfg = datasrc_config()
    if (cfg ~= nil) then
        c = cfg.credentials
    end

    if (c ~= nil and c.key ~= nil and c.key ~= "") then
        return true
    end
    return false
end

function vertical(ctx, domain)
    local c
    local cfg = datasrc_config()
    if (cfg ~= nil) then
        c = cfg.credentials
    end

    if (c == nil or c.key == nil or c.key == "") then
        return
    end

    for i=1,100 do
        local resp, err = request(ctx, {
            ['url']=build_url(domain, i),
            ['header']={['Authorization']="token " .. c.key},
        })
        if (err ~= nil and err ~= "") then
            log(ctx, "vertical request to service failed: " .. err)
            return
        elseif (resp.status_code < 200 or resp.status_code >= 400) then
            log(ctx, "vertical request to service returned with status: " .. resp.status)
            return
        end

        local d = json.decode(resp.body)
        if (d == nil) then
            log(ctx, "failed to decode the JSON response")
            return
        elseif (d.total_count == nil or d.total_count == 0 or #(d.items) == 0) then
            return
        end

        for _, item in pairs(d.items) do
            if (item ~= nil and item.url ~= nil and 
                item.url ~= "" and search_item(ctx, item.url)) then
                return
            end
        end
    end
end

function search_item(ctx, url)
    local resp, err = request(ctx, {['url']=url})
    if (err ~= nil and err ~= "") then
        log(ctx, "first search_item request to service failed: " .. err)
        return true
    elseif (resp.status_code < 200 or resp.status_code >= 400) then
        log(ctx, "first search_item request to service returned with status: " .. resp.status)
        return true
    end

    local d = json.decode(resp.body)
    if (d == nil) then
        log(ctx, "failed to decode the JSON response")
        return true
    elseif (d.download_url == nil or d.download_url == rate_error_url) then
        log(ctx, "API rate limit exceeded")
        return true
    end

    resp, err = request(ctx, {['url']=d.download_url})
    if (err ~= nil and err ~= "") then
        log(ctx, "second search_item request to service failed: " .. err)
        return
    elseif (resp.status_code < 200 or resp.status_code >= 400) then
        log(ctx, "second search_item request to service returned with status: " .. resp.status)
        return
    end

    send_names(ctx, resp.body)
end

function build_url(domain, pagenum)
    return "https://api.github.com/search/code?q=\"" .. domain .. "\"&page=" .. pagenum .. "&per_page=100"
end
