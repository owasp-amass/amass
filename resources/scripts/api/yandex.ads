-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local url = require("url")

name = "Yandex"
type = "api"

function start()
    set_rate_limit(2)
end

function check()
    local c
    local cfg = datasrc_config()
    if (cfg ~= nil) then
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
    if (cfg ~= nil) then
        c = cfg.credentials
    end

    if (c == nil or c.username == nil or 
        c.username == "" or c.key == nil or c.key == "") then
        return
    end

    local tlds = {"com", "com.tr", "ru"}
    local found = false
    for _, tld in pairs(tlds) do
        for i=1,20 do
            local ok = scrape(ctx, {['url']=build_url(domain, c.username, c.key, tld, i)})
            if not ok then
                break
            end
            found = true
        end

        if found then
            break
        end
    end
end

function build_url(domain, username, key, tld, pagenum)
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
