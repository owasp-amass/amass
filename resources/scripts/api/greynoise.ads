-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local json = require("json")

name = "Greynoise"
type = "api"

function start()
    set_rate_limit(1)
end

function vertical(ctx, domain)
    local resp, err = request(ctx, {['url']=build_url(domain)})
    if (err ~= nil and err ~= "") then
        log(ctx, "vertical request to service failed: " .. err)
        return
    elseif (resp.status_code < 200 or resp.status_code >= 400) then
        log(ctx, "vertical request to service returned with status: " .. resp.status)
        return
    end

    local d = json.decode(resp.body)
    if (d == nil) then
        log(ctx, "failed to decode the JSON response")
        return
    elseif (d.data == nil or d.count == 0) then
        return
    end

    for _, d in pairs(d.data) do
        if (d.rdns ~= nil and d.rdns ~= "" and in_scope(ctx, d.rdns)) then
            new_name(ctx, d.rdns)
            if (d.ip ~= nil and d.ip ~= "") then
                new_addr(ctx, d.ip, d.rdns)
            end
        end
    end
end

function build_url(domain)
    return "https://www.greynoise.io/api/enterprise/v2/experimental/gnql?size=1000&query=metadata.rdns:*." .. domain
end
