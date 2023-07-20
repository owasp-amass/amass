-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local json = require("json")

name = "LeakIX"
type = "api"

function start()
    set_rate_limit(2)
end

function vertical(ctx, domain)
    local c
    local cfg = datasrc_config()
    local headers = {
      ['Accept']="application/json",
    }
    if (cfg ~= nil) then
        c = cfg.credentials
    end
    if (c ~= nil and c.key ~= nil and c.key ~= "") then
       headers['api-key'] = c.key
    end

    local resp, err = request(ctx, {
        ['url']=vert_url(domain),
        ['header']=headers,
    })
    if (err ~= nil and err ~= "") then
        log(ctx, "vertical request to service failed: " .. err)
        return
    elseif (resp.status_code < 200 or resp.status_code >= 400) then
        log(ctx, "vertical request to service returned with status: " .. resp.status)
        return
    end

    local d = json.decode(resp.body)
    if (d == nil or #(d) == 0) then
        return
    end
    for _, node in pairs(d) do
        if (node ~= nil and node.subdomain ~= nil and node.subdomain ~= "") then
            new_name(ctx, node.subdomain)
        end
    end
end

function vert_url(domain)
    return "https://leakix.net/api/subdomains/" .. domain
end
