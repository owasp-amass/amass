-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

name = "HAW"
type = "archive"

function start()
    set_rate_limit(4)
end

function vertical(ctx, domain)
    local resp, err = request(ctx, {['url']=build_url(domain)})
    if (err ~= nil and err ~= "") then
        log(ctx, "vertical request to service failed: " .. err)
        return
    elseif (resp.status_code < 200 or resp.status_code >= 400) then
        log(ctx, "vertical request to service returned with status code: " .. resp.status)
        return
    end

    send_names(ctx, resp.body:gsub("<b>", ""))
end

function build_url(domain)
    return "https://haw.nsk.hr/proxy.php?subject=keywords&start=undefined&q=" .. domain
end
