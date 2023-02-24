-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local json = require("json")

name = "ThreatCrowd"
type = "api"

function start()
    set_rate_limit(10)
end

function vertical(ctx, domain)
    local url = "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=" .. domain

    local resp, err = request(ctx, {['url']=url})
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
    elseif (d.response_code == nil or d.response_code ~= "1") then
        return
    end

    if (d.subdomains ~= nil and #(d.subdomains) > 0) then
        for _, sub in pairs(d.subdomains) do
            if (sub ~= nil and sub ~= "") then
                new_name(ctx, sub)
            end
        end
    end

    if (d.resolutions ~= nil and #(d.resolutions) > 0) then
        for _, r in pairs(d.resolutions) do
            if (r ~= nil and r.ip_address ~= nil and r.ip_address ~= "") then
                new_addr(ctx, r.ip_address, domain)
            end
        end
    end
end
