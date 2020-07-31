-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "GitHub"
type = "api"

function start()
    setratelimit(7)
end

function vertical(ctx, domain)
    if (api == nil or api.key == nil or api.key == "") then
        return
    end

    for i=1,100 do
        local resp
        local vurl = buildurl(domain, i)
        -- Check if the response data is in the graph database
        if (api.ttl ~= nil and api.ttl > 0) then
            resp = obtain_response(vurl, api.ttl)
        end

        if (resp == nil or resp == "") then
            local err

            resp, err = request({
                url=vurl,
                headers={
                    ['Authorization']="token " .. api.key,
                    ['Content-Type']="application/json",
                },
            })
            if (err ~= nil and err ~= "") then
                return
            end

            if (api.ttl ~= nil and api.ttl > 0) then
                cache_response(vurl, resp)
            end
        end

        local d = json.decode(resp)
        if (d == nil or d['total_count'] == 0 or #(d.items) == 0) then
            return
        end

        for i, item in pairs(d.items) do
            search_item(ctx, item)
        end

        active(ctx)
        checkratelimit()
    end
end

function search_item(ctx, item)
    local info, err = request({
        url=item.url,
        headers={['Content-Type']="application/json"},
    })
    if (err ~= nil and err ~= "") then
        return
    end

    local data = json.decode(info)
    if (data == nil or data['download_url'] == nil) then
        return
    end

    local content, err = request({url=data['download_url']})
    if err == nil then
        sendnames(ctx, content)
    end
end

function buildurl(domain, pagenum)
    return "https://api.github.com/search/code?q=\"" .. domain .. "\"&page=" .. pagenum .. "&per_page=100"
end

function sendnames(ctx, content)
    local names = find(content, subdomainre)
    if names == nil then
        return
    end

    for i, v in pairs(names) do
        newname(ctx, v)
    end
end
