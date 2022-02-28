-- Copyright © by Jeff Foley 2022. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local json = require("json")

name = "LeakIX"
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
        ['url']=vert_url(domain),
        headers={
            ['api-key']=c.key,
            ['Accept']="application/json",
        },
    })
    if (err ~= nil and err ~= "") then
        log(ctx, "vertical request to service failed: " .. err)
        return
    end

    local j = json.decode(resp)
    if (j == nil or j.nodes == nil or #(j.nodes) == 0) then
        return
    end

    for _, node in pairs(j.nodes) do
        new_name(ctx, node.fqdn)
    end
end

function vert_url(domain)
    return "https://leakix.net/api/graph/hostname/" .. domain .. "?v%5B%5D=hostname&d=auto&l=1..5&f=3d-force"
end
