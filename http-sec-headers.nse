description = [[
Makes a request to the root folder ("/") of a web server and reports on the security headers that are missing from the data. This script mimics the functionality of https://securityheaders.io and is modeled after http-headers.nse.
]]

---
-- @args http-sec-headers.username basic auth username
-- @args http-sec-headers.password basic auth password
--
-- @usage
-- nmap --script http-sec-headers <target>
--
-- @output
-- 443/tcp open  https   syn-ack
-- | http-sec-headers:
-- |   missing:
-- |     Strict-Transport-Security: missing
-- |     X-Content-Type-Options: missing
-- |     Content-Security-Policy: missing
-- |     Referrer-Policy: missing
-- |   present:
-- |     X-XSS-Protection: 1; mode=block
-- |_    X-Frame-Options: SAMEORIGIN


-- HTTP Security Headers
-- rev 2.0 (2018-02-06)
-- Original NASL script by Jeffrey Stiles (@uthcr33p)(jeff@aerissecure.com)


categories = {"default", "discovery", "safe", "vuln"}
author = "Jeffrey Stiles"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"


portrule = shortport.http

---Get the best possible hostname for the given host. Like stdnse.get_hostname
-- but does not use reverse dns name.
local function get_hostname(host)
  if type(host) == "table" then
    return host.targetname or host.ip
  else
    return host
  end
end

action = function(host, port)
    local path = "/"
    local method = "GET"
    local https_redirect = false
    local redirect_location = nil
    local hostname = get_hostname(host)
    local auth = nil

    local username = stdnse.get_script_args(SCRIPT_NAME .. ".username")
    local password = stdnse.get_script_args(SCRIPT_NAME .. ".password")

    if username and password then
        auth = {username=username, password=password}
    end

    stdnse.verbose("Sending %s request to %s:%s", method, hostname, port.number)
    response = http.generic_request(hostname, port, method, path, {auth=auth})

    -- validate response
    if response == nil then
        return stdnse.format_output(false, "Request returned an empty response")
    end
    if response.rawheader == nil then
        return stdnse.format_output(false, "Request returned an empty rawheader table")
    end

    stdnse.verbose("Response status: %s (ssl=%s)", response.status, response.ssl)

    local code = tostring(response.status)

    -- check for http -> http redirect
    local redirect = not(code:match("^30[01237]$") == nil)
    if (response.ssl == false and redirect) then
        stdnse.verbose("redirect detected. target: "..response.header.location)
        -- response.header.location only exists for redirects
        if response.header.location:sub(1, #"https") == "https" then
            https_redirect = true
        end
    end

    local output = stdnse.output_table()
    output.missing = {}
    output.present = {}
    output.hostname = hostname
    if not response.ssl then
        output["redirect-http-to-https"] = https_redirect
    end
    if redirect then
        output["redirect-location"] = response.header.location
    end

    output.status = code
    if not(code:match("^[45]") == nil) then
        output.status = output.status .. " (possible error)"
    end

    -- restrict assets the browser can load
    local hdrval = response.header['content-security-policy']
    if hdrval == nil then
        output.missing["Content-Security-Policy"] = "missing"
    else
        output.present["Content-Security-Policy"] = hdrval
    end

    -- only supports one value: nosniff
    hdrval = response.header['x-content-type-options']
    if hdrval == nil then
        output.missing["X-Content-Type-Options"] = "missing"
    else
        output.present["X-Content-Type-Options"] = hdrval
    end

    -- prevent click-jacking. Values include DENY, SAMEORIGIN, ALLOW-FROM
    hdrval = response.header['x-frame-options']
    if hdrval == nil then
        output.missing["X-Frame-Options"] = "missing"
    else
        output.present["X-Frame-Options"] = hdrval
    end

    -- recommended value is "1" (enabled) and "mode=block" (instead of "=report")
    hdrval = response.header['x-xss-protection']
    if hdrval == nil then
        output.missing["X-XSS-Protection"] = "missing"
    else
        output.present["X-XSS-Protection"] = hdrval
    end

    -- controls information leaked in the referer header
    hdrval = response.header['referrer-policy']
    if hdrval == nil then
        output.missing["Referrer-Policy"] = "missing"
    else
        output.present["Referrer-Policy"] = hdrval
    end

    hdrval = response.header['feature-policy']
    if hdrval == nil then
        output.missing["Feature-Policy"] = "missing"
    else
        output.present["Feature-Policy"] = hdrval
    end

    --  minimum recommended value is 2592000 (30 days).
    hdrval = response.header['strict-transport-security']
    if response.ssl and hdrval == nil then
        output.missing["Strict-Transport-Security"] = "missing"
    else
        output.present["Strict-Transport-Security"] = hdrval
    end

    hdrval = response.header['expect-ct']
    if response.ssl and hdrval == nil then
        output.missing["Expect-CT"] = "missing"
    else
        output.present["Expect-CT"] = hdrval
    end


    hdrval = response.header['content-type']
    if hdrval ~= nil then
        stdnse.verbose("Response Content-Type: "..response.header['content-type'])
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