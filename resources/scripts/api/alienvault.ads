-- Copyright © by Jeff Foley 2017-2023. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
-- SPDX-License-Identifier: Apache-2.0

local json = require("json")

name = "AlienVault"
type = "api"

function start()
    set_rate_limit(1)
end

function vertical(ctx, domain)
    local c
    local cfg = datasrc_config()
    if (cfg ~= nil) then
        c = cfg.credentials
    end

    local hdrs = {['Content-Type']="application/json"}
    if (c ~= nil and c.key ~= nil and c.key ~= "") then
        hdrs["X-OTX-API-KEY"] = c.key
    end

    query(ctx, domain, hdrs, "passive_dns")
    query(ctx, domain, hdrs, "url_list")
end

function query(ctx, domain, hdrs, endpoint)
    local url = build_url(domain, endpoint)

    local j = extract(ctx, url, hdrs, endpoint)
    -- Check if there are additional pages to extract data from
    if (j == nil or endpoint ~= "url_list" or j.has_next == nil or not j.has_next or 
        j.full_size == nil or j.full_size == 0 or j.limit == nil or j.limit == 0) then
        return
    end

    local pages = math.ceil(j.full_size / j.limit)
    if (pages < 2) then
        return
    end

    for page=2,pages do
        extract(ctx, url .. "?page=" .. tostring(page), hdrs, endpoint)
    end
end

function extract(ctx, url, hdrs, endpoint)
    local resp, err = request(ctx, {
        ['url']=url,
        ['header']=hdrs,
    })
    if (err ~= nil and err ~= "") then
        log(ctx, endpoint .. " request to service failed: " .. err)
        return nil
    elseif (resp.status_code < 200 or resp.status_code >= 400) then
        log(ctx, endpoint .. " request to service returned with status: " .. resp.status)
        return nil
    end

    local d = json.decode(resp.body)
    if (d == nil) then
        log(ctx, "failed to decode the " .. endpoint .. " JSON response")
        return nil
    elseif (d.endpoint == nil or #(d.endpoint) == 0) then
        return nil
    end

    for _, e in pairs(d.endpoint) do
        if (e.hostname ~= nil and e.hostname ~= "") then
            new_name(ctx, e.hostname)
        end
    end
    return j
end

function build_url(domain, endpoint)
    return "https://otx.alienvault.com/api/v1/indicators/domain/" .. domain .. "/" .. endpoint
end

function horizontal(ctx, domain)
    local c
    local cfg = datasrc_config()
    if (cfg ~= nil) then
        c = cfg.credentials
    end

    local hdrs = {['Content-Type']="application/json"}
    if (c ~= nil and c.key ~= nil and c.key ~= "") then
        hdrs["X-OTX-API-KEY"] = c.key
    end

    local emails = get_whois_emails(ctx, domain, hdrs)
    if (#emails == 0) then
        return
    end

    for _, email in pairs(emails) do
        reverse_whois(ctx, domain, hdrs, email)
    end
end

function get_whois_emails(ctx, domain, hdrs)
    local emails = {}

    local resp, err = request(ctx, {
        ['url']=whois_url(domain),
        ['header']=hdrs,
    })
    if (err ~= nil and err ~= "") then
        log(ctx, "whois request to service failed: " .. err)
        return emails
    elseif (resp.status_code < 200 or resp.status_code >= 400) then
        log(ctx, "whois request to service returned with status: " .. resp.status)
        return emails
    end

    local d = json.decode(resp.body)
    if (d == nil) then
        log(ctx, "failed to decode the whois JSON response")
        return emails
    elseif (d.count == nil or d.count == 0 or #(d.data) == 0) then
        return emails
    end

    for _, e in pairs(d.data) do
        if (e.key ~= nil and e.key == "emails") then
            local parts = split(e.value, "@")

            if (#parts == 2 and in_scope(ctx, parts[2])) then table.insert(emails, e.value) end
        end
    end
    return emails
end

function whois_url(domain)
    return "https://otx.alienvault.com/otxapi/indicator/domain/whois/" .. domain
end

function reverse_whois(ctx, domain, hdrs, email)
    local resp, err = request(ctx, {
        ['url']=reverse_whois_url(email),
        ['header']=hdrs,
    })
    if (err ~= nil and err ~= "") then
        log(ctx, "reverse_whois request to service failed: " .. err)
        return
    elseif (resp.status_code < 200 or resp.status_code >= 400) then
        log(ctx, "reverse_whois request to service returned with status: " .. resp.status)
        return
    end

    local d = json.decode("{\"results\":" .. resp.body .. "}")
    if (d == nil) then
        log(ctx, "failed to decode the reverse whois JSON response")
        return
    elseif (d.results == nil or #(d.results) == 0) then
        return
    end

    for _, e in pairs(d.results) do
        if (e.domain ~= nil and e.domain ~= "") then
            associated(ctx, domain, e.domain)
        end
    end
end

function reverse_whois_url(email)
    return "https://otx.alienvault.com/otxapi/indicator/email/whois/" .. email
end

function split(str, delim)
    local result = {}
    local pattern = "[^%" .. delim .. "]+"

    local matches = find(str, pattern)
    if (matches == nil or #matches == 0) then return result end

    for _, match in pairs(matches) do
        table.insert(result, match)
    end
    return result
end
