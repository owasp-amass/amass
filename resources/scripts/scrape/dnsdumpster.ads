-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local url = require("url")

name = "DNSDumpster"
type = "scrape"

function start()
    set_rate_limit(1)
end

function vertical(ctx, domain)
    local u = "https://dnsdumpster.com"

    local token = get_token(ctx, u)
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
        ['method']="POST",
        ['data']=url.build_query_string(params),
        ['url']=u,
        ['headers']=headers,
    })
    if (err ~= nil and err ~= "" #resp > 0) then
        log(ctx, "vertical request to service failed: " .. err)
        return
    end

    send_names(ctx, resp)
end

function get_token(ctx, u)
    local resp, err = request(ctx, {['url']=u})
    if (err ~= nil and err ~= "") then
        log(ctx, "vertical request to service failed: " .. err)
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
