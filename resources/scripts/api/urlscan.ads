-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local json = require("json")

name = "URLScan"
type = "api"

function start()
    set_rate_limit(5)
end

function vertical(ctx, domain)
    local url = "https://urlscan.io/api/v1/search/?q=domain:" .. domain

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
    elseif (d.total == nil or d.results == nil or #(d.results) == 0) then
        return
    end

    if d.total <= 0 then
        subs(ctx, submission(ctx, domain))
        return
    end

    for _, r in pairs(d.results) do
        if (r['_id'] ~= nil and r['_id'] ~= "") then
            subs(ctx, r['_id'])
        end
    end
end

function subs(ctx, id)
    local url = "https://urlscan.io/api/v1/result/" .. id .. "/"

    local resp, err = request(ctx, {['url']=url})
    if (err ~= nil and err ~= "") then
        log(ctx, "subs request to service failed: " .. err)
        return
    elseif (resp.status_code < 200 or resp.status_code >= 400) then
        log(ctx, "subs request to service returned with status: " .. resp.status)
        return
    end

    local d = json.decode(resp.body)
    if (d == nil) then
        log(ctx, "failed to decode the JSON subs response")
        return
    elseif (d.lists == nil or #(d['lists'].linkDomains) == 0) then
        return
    end

    for _, sub in pairs(d['lists'].linkDomains) do
        if (sub ~= nil and sub ~= "") then
            new_name(ctx, sub)
        end
    end
end

function submission(ctx, domain)
    local c
    local cfg = datasrc_config()
    if (cfg ~= nil) then
        c = cfg.credentials
    end

    if (c == nil or c.key == nil or c.key == "") then
        return ""
    end

    local headers = {
        ['Content-Type']="application/json",
        ['API-Key']=c.key,
    }

    local resp, body, err
    body, err = json.encode({
        ['url']=domain,
        ['public']="on",
        ['customagent']="OWASP Amass", 
    })
    if (err ~= nil and err ~= "") then
        return ""
    end

    resp, err = request(ctx, {
        ['url']="https://urlscan.io/api/v1/scan/",
        ['method']="POST",
        ['header']=headers,
        ['body']=body,
    })
    if (err ~= nil and err ~= "") then
        log(ctx, "scan request to service failed: " .. err)
        return
    elseif (resp.status_code < 200 or resp.status_code >= 400) then
        log(ctx, "scan request to service returned with status: " .. resp.status)
        return
    end

    local d = json.decode(resp.body)
    if (d == nil) then
        log(ctx, "failed to decode the JSON scan response")
        return ""
    elseif (d.message ~= "Submission successful") then
        log(ctx, "message included in the scan response: " .. d.message)
        return ""
    elseif (d.results == nil or #(d.results) == 0) then
        return ""
    end

    -- Keep this data source active while waiting for the scan to complete
    while(true) do
        resp, err = request(ctx, {['url']=d.api})
        if (err == nil and resp.status_code ~= 404) then
            break
        end
        -- A large pause between these requests
        for _=1,3 do check_rate_limit() end
    end

    return d.uuid
end
