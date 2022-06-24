-- Copyright 2022 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")
local url = require("url")

name = "FOFA"
type = "api"

function start()
    set_rate_limit(1)
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
        c.username == "" or c.key == nil or c.key == "") then
        return
    end

    local p = 1
    while(true) do
        local resp, err = request(ctx, {
            ['url']=build_url(domain, c.username, c.key, p)
        })
        if (err ~= nil and err ~= "") then
            log(ctx, "vertical request to service failed: " .. err)
            return
        end

        local j = json.decode(resp)
        if (j == nil or j.error == true or j.size == 0) then
            if (j.errmsg ~= nil and j.errmsg ~= "") then
                log(ctx, "vertical request to service failed: " .. j.errmsg)
            end

            return
        end

        for _, result in pairs(j.results) do
            send_names(ctx, result)
        end

        if j.size < 10000 then
            return
        end
        i = i + 1
    end
end

function build_url(domain, username, key, pagenum)
    local query = base64_encode("domain=\"" .. domain .. "\"")
    local params = {
        ['full']="true",
        ['fields']="host",
        ['size']="10000",
        ['page']=pagenum,
        ['email']=username,
        ['key']=key,
        ['qbase64']=query,
    }

    return "https://fofa.info/api/v1/search/all?" .. url.build_query_string(params)
end

function base64_encode(data)
    local b = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    return ((data:gsub('.', function(x) 
        local r,b='',x:byte()
        for i=8,1,-1 do r=r..(b%2^i-b%2^(i-1)>0 and '1' or '0') end
        return r;
    end)..'0000'):gsub('%d%d%d?%d?%d?%d?', function(x)
        if (#x < 6) then return '' end
        local c=0
        for i=1,6 do c=c+(x:sub(i,i)=='1' and 2^(6-i) or 0) end
        return b:sub(c+1,c+1)
    end)..({ '', '==', '=' })[#data%3+1])
end
