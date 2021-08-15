-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local url = require("url")

name = "DNSDumpster"
type = "scrape"

function start()
    set_rate_limit(1)
end

function vertical(ctx, domain)
    local token = get_token(ctx)
    if token == "" then
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

    local resp, err = request(ctx, {
        url="https://dnsdumpster.com",
        method="POST",
        data=url.build_query_string(params),
        headers=headers,
    })
    if (err == nil and #resp > 0) then
        send_names(ctx, resp)
    end
end

function get_token(ctx)
    local resp, err = request(ctx, {url="https://dnsdumpster.com"})
    if (err ~= nil and err ~= "") then
        return ""
    end

    local matches = submatch(resp, '<input type="hidden" name="csrfmiddlewaretoken" value="([a-zA-Z0-9]*)">')
    if (matches == nil or #matches == 0) then
        return ""
    end

    local match = matches[1]
    if (match == nil or #match ~= 2) then
        return ""
    end

    return match[2]
end
