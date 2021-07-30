-- Copyright 2017-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "Fofa"
type = "api"

function start()
    setratelimit(1)
end

function check()
    local c
    local cfg = datasrc_config()
    if cfg ~= nil then
        c = cfg.credentials
    end

    if (c ~= nil and c.username ~= nil and
        c.key ~= nil and c.username ~= "" and c.key ~= "") then
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

    if (c == nil or c.username == nil or
        c.key == nil or c.username == "" or c.key == "") then
        return
    end

    local resp, err = request(ctx, {['url']=apiurl(c, domain)})
    if (err ~= nil and err ~= "") then
        return
    end

    local d = json.decode(resp)
    if (d == nil or #(d.results) == 0) then
        return
    end

    local urlpattern = "://"
    for i, sub in pairs(d.results) do
        local matches = find(sub, urlpattern)
        if (matches ~= nil and #matches ~= 0) then
            continue
        end

        newname(ctx, sub)
    end
end

function apiurl(c, domain)
    local query = base64(("domain=\"" .. domain .. "\"")
    return "https://fofa.so/api/v1/search/all?full=true&fields=host&page=1&size=10000&email=" .. c.username .. "&key=" .. c.key .. "&qbase64=" .. query
end
