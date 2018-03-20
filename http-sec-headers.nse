description = [[
Makes a request to the root folder ("/") of a web server and reports on the security headers that are missing from the response. This script mimics the functionality of https://securityheaders.io and is modeled after http-headers.nse.
]]

---
-- @args
--
-- @usage
-- nmap --script http-sec-headers <target>
--
-- @output
-- 443/tcp open  https   syn-ack
-- | http-sec-headers:
-- |   missing:
-- |     Public-Key-Pins: missing
-- |     Strict-Transport-Security: missing
-- |     X-Content-Type-Options: missing
-- |     Content-Security-Policy: missing
-- |     Referrer-Policy: missing
-- |   present:
-- |     X-XSS-Protection: 1; mode=block
-- |_    X-Frame-Options: SAMEORIGIN


-- HTTP Security Headers
-- rev 1.0 (2016-07-25)
-- Original NASL script by Jeffrey Stiles (@uthcr33p)(jeff@aerissecure.com)


categories = {"default", "discovery", "safe", "vuln"}
author = "Jeffrey Stiles"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"


portrule = shortport.http

action = function(host, port)
    local path = "/"
    local request_type = "HEAD"
    local proto = "http"

    if port.version.service_tunnel == "ssl" or string.find(port.service, "https") then
        proto = "https"
    end

    -- try HEAD request first
    local status, result
    status, result = http.can_use_head(host, port, nil, path)

    -- if HEAD failed, use GET
    if status == false then
        stdnse.debug1("HEAD request failed, falling back to GET")
        result = http.get(host, port, path)
        request_type = "GET"
    end

    if result == nil then
        return stdnse.format_output(false, "Header request failed")
    end

    if result.rawheader == nil then
        return stdnse.format_output(false, "Header request didn't return a proper header")
    end

    local output = stdnse.output_table()
    output.missing = {}
    output.present = {}

    -- restrict assets the browser can load
    local hdrval = result.header['content-security-policy']
    if hdrval == nil then
        output.missing["Content-Security-Policy"] = "missing"
    else
        output.present["Content-Security-Policy"] = hdrval
    end

    -- only supports one value: nosniff
    hdrval = result.header['x-content-type-options']
    if hdrval == nil then
        output.missing["X-Content-Type-Options"] = "missing"
    else
        output.present["X-Content-Type-Options"] = hdrval
    end

    -- prevent click-jacking. Values include DENY, SAMEORIGIN, ALLOW-FROM
    hdrval = result.header['x-frame-options']
    if hdrval == nil then
        output.missing["X-Frame-Options"] = "missing"
    else
        output.present["X-Frame-Options"] = hdrval
    end

    -- recommended value is "1" (enabled) and "mode=block" (instead of "=report")
    hdrval = result.header['x-xss-protection']
    if hdrval == nil then
        output.missing["X-XSS-Protection"] = "missing"
    else
        output.present["X-XSS-Protection"] = hdrval
    end

    -- controls information leaked in the referer header
    hdrval = result.header['referrer-policy']
    if hdrval == nil then
        output.missing["Referrer-Policy"] = "missing"
    else
        output.present["Referrer-Policy"] = hdrval
    end

    --  minimum recommended value is 2592000 (30 days).
    hdrval = result.header['strict-transport-security']
    if proto == "https" and hdrval == nil then
        output.missing["Strict-Transport-Security"] = "missing"
    else
        output.present["Strict-Transport-Security"] = hdrval
    end

    -- allows pinning of specific certs
    hdrval = result.header['public-key-pins']
    if proto == "https" and hdrval == nil then
        output.missing["Public-Key-Pins"] = "missing"
    else
        output.present["Public-Key-Pins"] = hdrval
    end

    hdrval = result.header['content-type']
    if hdrval ~= nil then
        stdnse.verbose("Response Content-Type: "..result.header['content-type'])
    end

    -- remove empty sections
    if next(output.missing) == nil then
        output.missing = nil
    end

    if next(output.present) == nil then
        output.present = nil
    end

    return output

end