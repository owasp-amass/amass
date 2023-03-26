-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

name = "SpyOnWeb"
type = "scrape"

function start()
    set_rate_limit(2)
end

function horizontal(ctx, domain)
    local resp, err = request(ctx, {['url']=build_url(domain)})
    if (err ~= nil and err ~= "") then
        log(ctx, "horizontal request to service failed: " .. err)
        return
    elseif (resp.status_code < 200 or resp.status_code >= 400) then
        log(ctx, "horizontal request to service returned with status code: " .. resp.status)
        return
    end

    local pattern = "\"/go/([a-z0-9-]{2,63}[.][a-z]{2,3}([a-z]{2}|))\""
    local matches = submatch(resp.body, pattern)
    if (matches == nil or #matches == 0) then
        log(ctx, "failed to discover registered domain names in the response")
        return
    end

    for _, match in pairs(matches) do
        if (match ~= nil and #match >= 2 and match[2] ~= "") then
            associated(ctx, domain, match[2])
        end
    end
end

function build_url(domain)
    return "https://spyonweb.com/" .. domain
end
