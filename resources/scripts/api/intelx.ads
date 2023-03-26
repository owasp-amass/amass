-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local json = require("json")

name = "IntelX"
type = "api"
useragent = "OWASP Amass"
host = "https://2.intelx.io/"
max = 1000

function start()
    set_rate_limit(2)
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

    phonebook(ctx, domain, c.key)
end

function phonebook(ctx, domain, key)
    local id = search(ctx, "", domain, key)
    if (id == "") then
        return
    end

    local status = 3
    local limit = 1000
    while status == 0 or status == 3 do
        local resp = results(ctx, id, limit, key)
        if (resp == nil) then
            break
        end

        status = resp.status
        if ((status == 0 or status == 1) and resp.selectors ~= nil and #(resp.selectors) > 0) then
            if (#(resp.selectors) < limit) then
                limit = limit - #(resp.selectors)
            end

            for _, s in pairs(resp.selectors) do
                local t = s.selectortype
        
                if (t == 2 or t == 3 or t == 23) then
                    print(s.selectorvalue)
                    send_names(ctx, s.selectorvalue)
                end
            end
        end

        if (limit <= 0) then
            break
        end
    end
end

function search(ctx, domain, key)
    local body, resp, err

    body, err = json.encode({
        ['term']=domain, 
        ['lookuplevel']=0,
        ['timeout']=0,
        ['maxresults']=max,
        ['datefrom']="",
        ['dateto']="",
        ['sort']=0,
        ['media']=0,
    })
    if (err ~= nil and err ~= "") then
        return ""
    end

    resp, err = request(ctx, {
        ['url']=host .. "phonebook/search",
        ['method']="POST",
        ['header']={
            ['x-key']=key,
            ['Content-Type']="application/json",
            ['User-Agent']=useragent,
            ['Connection']="keep-alive",
        },
        ['body']=body,
    })
    if (err ~= nil and err ~= "") then
        log(ctx, "search request to service failed: " .. err)
        return ""
    elseif (resp.status_code < 200 or resp.status_code >= 400) then
        log(ctx, "search request to service returned with status: " .. resp.status)
        return ""
    end

    local d = json.decode(resp.body)
    if (d == nil) then
        log(ctx, "failed to decode the JSON response")
        return ""
    elseif (d.status == nil or d.id == nil or d.status ~= 0) then
        return ""
    end

    return d.id
end

function results(ctx, id, limit, key)
    local resp, err = request(ctx, {
        ['url']=host .. "phonebook/search/result?id=" .. id .. "&limit=" .. limit,
        ['header']={
            ['x-key']=key,
            ['User-Agent']=useragent,
            ['Connection']="keep-alive",
        },
    })
    if (err ~= nil and err ~= "") then
        log(ctx, "result request to service failed: " .. err)
        return nil
    elseif (resp.status_code < 200 or resp.status_code >= 400) then
        log(ctx, "result request to service returned with status: " .. resp.status)
        return nil
    end

    local d = json.decode(resp.body)
    if (d == nil) then
        log(ctx, "failed to decode the JSON response")
        return nil
    elseif (d.status == nil) then
        return nil
    end

    return d
end
