-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

name = "Active Crawl"
type = "crawl"

local cfg
local max_links = 50

function start()
    cfg = config()
end

function vertical(ctx, domain)
    if (cfg == nil or cfg.mode ~= "active") then
        return
    end

    start_crawling(ctx, domain)
end

function resolved(ctx, name, domain, records)
    if (cfg == nil or cfg.mode ~= "active") then
        return
    end
    -- Do not crawl names without a CNAME or A/AAAA records
    if (#records == 0 or (not has_cname(records) and not has_addr(records))) then
        return
    end
    
    start_crawling(ctx, name)
end

function has_cname(records)
    if (#records == 0) then
        return false
    end

    for _, rec in pairs(records) do
        if (rec.rrtype == 5) then
            return true
        end
    end

    return false
end

function has_addr(records)
    if (#records == 0) then
        return false
    end

    for _, rec in pairs(records) do
        if (rec.rrtype == 1 or rec.rrtype == 28) then
            return true
        end
    end

    return false
end

function start_crawling(ctx, fqdn)
    for _, port in pairs(cfg['scope'].ports) do
        local protocol = "http://"
        if (port ~= 80) then
            protocol = "https://"
        end

        crawl(ctx, protocol .. fqdn .. ":" .. tostring(port), max_links)
    end
end
