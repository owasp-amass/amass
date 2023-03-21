-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local json = require("json")

name = "ONYPHE"
type = "api"

function start()
    set_rate_limit(1)
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

    for page=1,1000 do
        local resp, err = request(ctx, {
            ['url']=vert_url(domain, page),
            ['header']={
                ['Content-Type']="application/json",
                ['Authorization']="apikey " .. c.key,
            },
        })
        if (err ~= nil and err ~= "") then
            log(ctx, "vertical request to service failed: " .. err)
            return
        elseif (resp.status_code < 200 or resp.status_code >= 400) then
            log(ctx, "vertical request to service returned with status: " .. resp.status)
            return
        end

        d = json.decode(resp.body)
        if (d == nil) then
            log(ctx, "failed to decode the JSON response")
            return
        elseif (d.count == nil or d.count == 0 or #(d.results) == 0) then
            return
        end

        for _, r in pairs(d.results) do
            if (r['@category'] == "resolver") then
                new_name(ctx, r['hostname'])
                new_addr(ctx, r['ip'], r['hostname'])
            else
                for _, name in pairs(r['hostname']) do
                    if in_scope(ctx, name) then
                        new_name(ctx, name)
                    end
                end
                if (r['subject'] ~= nil) then
                    for _, name in pairs(r['subject']['altname']) do
                        if in_scope(ctx, name) then
                            new_name(ctx, name)
                        end
                    end
                end
                if (r['subdomains'] ~= nil) then
                    for _, name in pairs(r['subdomains']) do
                        if in_scope(ctx, name) then
                            new_name(ctx, name)
                        end
                    end
                end
            end

            if (r['reverse'] ~= nil and in_scope(ctx, r['reverse'])) then
                new_name(ctx, r['reverse'])
            end

            if (r['forward'] ~= nil and in_scope(ctx, r['forward'])) then
                new_name(ctx, r['forward'])
            end
        end

        if (page == d.max_page) then
            break
        end
    end
end

function vert_url(domain, pagenum)
    return "https://www.onyphe.io/api/v2/summary/domain/" .. domain .. "?page=" .. pagenum
end

function horizontal(ctx, domain)
    local c
    local cfg = datasrc_config()
    if (cfg ~= nil) then
        c = cfg.credentials
    end

    if (c == nil or c.key == nil or c.key == "") then
        return
    end

    local ips, err = resolve(ctx, domain, "A")
    if (err ~= nil and err ~= "") then
        log(ctx, "horizontal resolve request to service failed: " .. err)
        return
    end

    for _, ip in pairs(ips) do
        for page=1,1000 do
            local resp, err = request(ctx, {
                ['url']=horizon_url(ip, page),
                ['header']={
                    ['Content-Type']="application/json",
                    ['Authorization']="apikey " .. c.key,
                },
            })
            if (err ~= nil and err ~= "") then
                log(ctx, "horizontal request to service failed: " .. err)
                return
            elseif (resp.status_code < 200 or resp.status_code >= 400) then
                log(ctx, "horizontal request to service returned with status: " .. resp.status)
                return
            end

            d = json.decode(resp.body)
            if (d == nil) then
                log(ctx, "failed to decode the JSON horizontal response")
                return
            elseif (d.count == nil or d.count == 0 or #(d.results) == 0) then
                return
            end

            for _, r in pairs(d.results) do
                if (r['@category'] == "resolver") then
                    associated(ctx, domain, r['domain'])
                elseif (r['@category'] == "datascan" and r['domain'] ~= nil) then
                    for _, name in pairs(r['domain']) do
                        associated(ctx, domain, name)
                    end
                end
            end

            if (page == r.max_page) then
                break
            end
        end
    end
end

function horizon_url(ip, pagenum)
    return "https://www.onyphe.io/api/v2/summary/ip/" .. ip .. "?page=" .. pagenum
end
