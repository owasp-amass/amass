-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

local json = require("json")

name = "URLScan"
type = "api"

function start()
    set_rate_limit(1)
end

function vertical(ctx, domain)
    local id = submission(ctx, domain)
    if (id ~= "") then
        scrape(ctx, {url="https://urlscan.io/api/v1/result/" .. id})
    end

    local last = nil
    while(true) do
        local resp, err = request(ctx, {['url']=api_url(domain, last)})
        if (err ~= nil and err ~= "") then
            return
        end

        local d = json.decode(resp)
        if (d == nil or d.total == 0) then
            return
        end

        for i, r in pairs(d.results) do
            scrape(ctx, {url=r['result']})
            check_rate_limit()

            last = tostring(r['sort'][1]) .. "," .. r['sort'][2]
        end

        if d.has_more == false then
            break
        end
    end
end

function api_url(domain, last)
    local url = "https://urlscan.io/api/v1/search/?q=domain:" .. domain
    if (last ~= nil) then
        url = url .. "&search_after=" .. last
    end

    return url
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
        for var=1,10 do check_rate_limit() end
    end

	return d.uuid
end
