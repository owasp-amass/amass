-- Copyright © by Jeff Foley 2021-2022. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local url = require("url")

name = "DNSDumpster"
type = "scrape"

function start()
    set_rate_limit(1)
end

function vertical(ctx, domain)
    local u = "https://dnsdumpster.com"

    local token = get_token(ctx, u)
    if (token == "") then
        return
    end

    local headers = {
        ['Content-Type']="application/x-www-form-urlencoded",
        ['Referer']=u,
        ['X-CSRF-Token']=token,
    }

    local params = {
        ['csrfmiddlewaretoken']=token,
        ['targetip']=domain,
        ['user']="free"
    }

    scrape(ctx, {
        ['url']=u,
        ['method']="POST",
        ['header']=headers,
        ['body']=url.build_query_string(params),
    })
end

function get_token(ctx, u)
    local resp, err = request(ctx, {['url']=u})
    if (err ~= nil and err ~= "") then
        log(ctx, "get_token request to service failed: " .. err)
        return ""
    elseif (resp.status_code < 200 or resp.status_code >= 400) then
        log(ctx, "get_token request to service returned with status code: " .. resp.status)
        return ""
    end

    local matches = submatch(resp.body, '<input type="hidden" name="csrfmiddlewaretoken" value="([a-zA-Z0-9]*)">')
    if (matches == nil or #matches == 0) then
        log(ctx, "failed to discover the token in the response body")
        return ""
    end

    local match = matches[1]
    if (match == nil or #match ~= 2) then
        return ""
    end
    return match[2]
end
