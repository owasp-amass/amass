-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "URLScan"
type = "api"

function start()
    set_rate_limit(2)
end

function vertical(ctx, domain)
    local url = "https://urlscan.io/api/v1/search/?q=domain:" .. domain
    local resp, err = request(ctx, {['url']=url})
    if (err ~= nil and err ~= "") then
        log(ctx, "vertical request to service failed: " .. err)
        return
    end

    local d = json.decode(resp)
    if (d == nil or d.total == nil or d.results == nil or #(d.results) == 0) then
        return
    end

    if d.total > 0 then
        for i, r in pairs(d.results) do
            subs(ctx, r['_id'])
        end
        return
    end

    subs(ctx, submission(ctx, domain))
end

function subs(ctx, id)
    if id == "" then
        return
    end

    local url = "https://urlscan.io/api/v1/result/" .. id .. "/"
    local resp, err = request(ctx, {['url']=url})
    if (err ~= nil and err ~= "") then
        log(ctx, "result request to service failed: " .. err)
        return
    end

    local d = json.decode(resp)
    if (d == nil or d.lists == nil or 
        d.lists.linkDomains == nil or #(d.lists.linkDomains) == 0) then
        return
    end

    for i, sub in pairs(d.lists.linkDomains) do
        new_name(ctx, sub)
    end
end

function submission(ctx, domain)
    local c
    local cfg = datasrc_config()
    if cfg ~= nil then
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
        public="on",
        customagent="OWASP Amass", 
    })
    if (err ~= nil and err ~= "") then
        return ""
    end

    resp, err = request(ctx, {
        ['method']="POST",
        ['data']=body,
        ['url']="https://urlscan.io/api/v1/scan/",
        ['headers']=headers,
    })
    if (err ~= nil and err ~= "") then
        log(ctx, "scan request to service failed: " .. err)
        return ""
    end

    local d = json.decode(resp)
    if (d == nil or d.message ~= "Submission successful" or #(d.results) == 0) then
        return ""
    end

    -- Keep this data source active while waiting for the scan to complete
	while(true) do
        _, err = request(ctx, {['url']=d.api})
		if (err == nil or err ~= "404 Not Found") then
			break
        end
        -- A large pause between these requests
        for var=1,5 do check_rate_limit() end
	end

	return d.uuid
end
