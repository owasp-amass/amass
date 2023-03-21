-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local json = require("json")

name = "Mnemonic"
type = "api"

function start()
    set_rate_limit(1)
end

function vertical(ctx, domain)
    local resp, err = request(ctx, {['url']=api_url(domain)})
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
    elseif (d.data == nil or d.responseCode ~= 200 or d.count == 0) then
        return
    end

    for _, tb in pairs(d.data) do
        if (tb ~= nil and tb.query ~= nil and tb.rrtype ~= nil) then
            if (tb.query ~= "" and in_scope(ctx, tb.query)) then
                new_name(ctx, tb.query)
            end
            if (tb.rrtype == "a" or tb.rrtype == "aaaa") then
                new_addr(ctx, tb.answer, tb.query)
            end
            if (tb.rrtype == "cname") then
                new_name(ctx, tb.answer)
            end
        end
    end
end

function api_url(domain)
    return "https://api.mnemonic.no/pdns/v3/" .. domain .. "?limit=1000"
end
