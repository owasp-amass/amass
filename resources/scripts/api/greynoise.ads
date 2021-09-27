-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

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
    end

    local j = json.decode(resp)
    if (j == nil or j.count == 0) then
        return
    end

    for _, d in pairs(j.data) do
        new_name(ctx, d.rdns)
        new_addr(ctx, d.ip, d.rdns)
    end
end

function build_url(domain)
    return "https://greynoise-prod.herokuapp.com/enterprise/v2/experimental/gnql?size=1000&query=metadata.rdns:*." .. domain
end
