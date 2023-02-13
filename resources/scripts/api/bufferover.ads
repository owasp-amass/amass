-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

name = "BufferOver"
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

    local ok = commercial_api_query(ctx, domain, c.key)
    if not ok then
        scrape(ctx, {
            url=build_url(domain),
            headers={['x-api-key']=c.key},
        })
    end
end

function commercial_api_query(ctx, domain, key)
    local resp, err = request(ctx, {
        url="https://bufferover-run-tls.p.rapidapi.com/ipv4/dns?q=." .. domain,
        headers={
            ['x-rapidapi-host']="bufferover-run-tls.p.rapidapi.com",
            ['x-rapidapi-key']=key,
        },
    })
    if (err ~= nil and err ~= "") then
        return false
    end

    send_names(ctx, resp)
    return true
end

function build_url(domain)
    return "https://tls.bufferover.run/dns?q=." .. domain
end
