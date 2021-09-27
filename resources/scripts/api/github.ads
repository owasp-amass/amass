-- Copyright 2020-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "GitHub"
type = "api"

function start()
    set_rate_limit(7)
end

function check()
    local c
    local cfg = datasrc_config()
    if cfg ~= nil then
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
    if cfg ~= nil then
        c = cfg.credentials
    end

    if (c == nil or c.key == nil or c.key == "") then
        return
    end

    for i=1,100 do
        local resp, err = request(ctx, {
            ['url']=build_url(domain, i),
            headers={['Authorization']="token " .. c.key},
        })
        if (err ~= nil and err ~= "") then
            log(ctx, "vertical request to service failed: " .. err)
            return
        end

        local d = json.decode(resp)
        if (d == nil or d['total_count'] == 0 or #(d.items) == 0) then
            return
        end

        for i, item in pairs(d.items) do
            search_item(ctx, item)
        end
    end
end

function search_item(ctx, item)
    local info, err = request(ctx, {['url']=item.url})
    if (err ~= nil and err ~= "") then
        log(ctx, "first search_item request to service failed: " .. err)
        return
    end

    local data = json.decode(info)
    if (data == nil or data['download_url'] == nil) then
        return
    end

    local content, err = request(ctx, {['url']=data['download_url']})
    if err ~= nil and err ~= "" then
        log(ctx, "second search_item request to service failed: " .. err)
    end

    send_names(ctx, content)
end

function build_url(domain, pagenum)
    return "https://api.github.com/search/code?q=\"" .. domain .. "\"&page=" .. pagenum .. "&per_page=100"
end
