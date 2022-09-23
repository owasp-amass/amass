-- Copyright © by Jeff Foley 2022. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local json = require("json")

name = "BeVigil"
type = "api"

function start()
    set_rate_limit(2)
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

    local resp, err = request(ctx, {
        url=build_url(domain),
        headers={
            ['X-Access-Token']=c.key,
            ['User-Agent']="OWASP Amass"
        },
    })
    if (err ~= nil and err ~= "") then
        log(ctx, "vertical request to service failed: " .. err)
        return
    end

    local d = json.decode(resp)
    if (d == nil or d.subdomains == nil or #(d.subdomains) == 0) then
        return
    end

    for _, sub in pairs(d.subdomains) do
        new_name(ctx, sub)
    end

end

function build_url(domain)
    return "http://osint.bevigil.com/api/" .. domain .. "/subdomains/"
end
