-- Copyright 2022 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local url = require("url")

name = "Yandex"
type = "scrape"

function start()
    set_rate_limit(2)
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

    local tlds = {"com", "com.tr", "ru"}

    for _, tld in pairs(tlds) do
        local correct_tld = false
        for i=1,10 do
            local found = scrape(ctx, {
                ['url']=build_url(c.username, c.key, domain, tld, i),
            })

            if not found then
                break
            elseif i == 1 then
                correct_tld = true
            end
        end

        if correct_tld then
            break
        end
    end
end

function build_url(username, key, domain, tld, pagenum)
    local query = "site:" .. domain .. " -www"
    local params = {
        ['maxpassages']=1,
        ['user']=username,
        ['key']=key,
        ['query']=query,
        ['page']=pagenum,
    }

    return "https://yandex." .. tld .. "/search/xml?" .. url.build_query_string(params)
end
