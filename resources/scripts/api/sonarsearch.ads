-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "SonarSearch"
type = "api"

function start()
    set_rate_limit(1)
end

function vertical(ctx, domain)
    local p = 0
    while(true) do
        local vurl = "https://sonar.omnisint.io/subdomains/" .. domain .. "?page=" .. p
        local resp, err = request(ctx, {['url']=vurl})
        if (err ~= nil and err ~= "") then
            log(ctx, "vertical request to service failed: " .. err)
            return
        end
        resp = "{\"subdomains\":" .. resp .. "}"

        local d = json.decode(resp)
        if (d == nil or d.subdomains == nil or #(d.subdomains) == 0) then
            return
        end

        for _, sub in pairs(d.subdomains) do
            new_name(ctx, sub)
        end

        p = p + 1
    end
end
