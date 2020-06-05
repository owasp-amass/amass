name = "DNSTable"
type = "scrape"

function start()
    setratelimit(1)
end

function vertical(ctx, domain)
    local page, err = request({
        url=buildurl(domain),
    })
    if (err ~= nil and err ~= '') then
        return
    end

    local names = find(page, subdomainre)
    if names == nil then
        return
    end

    for i, v in pairs(names) do
        newname(ctx, v)
    end
end

function buildurl(domain)
    return "https://dnstable.com/domain/" .. domain
end