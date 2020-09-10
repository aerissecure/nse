local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local vulns = require "vulns"

description = [[
Attempts to partially detect the BREACH HTTP compression vulnerability (CVE-2013-3587).

The script can only confirm if an HTTPS request successfully completes with a Referer header and that the response uses HTTP compression (gzip, DEFLATE). However, details for additional vulnerability confirmation are provided in the vuln description output.

References:
* http://www.breachattack.com/
* https://blog.qualys.com/ssllabs/2013/08/07/defending-against-the-breach-attack
* https://blog.cloudflare.com/a-solution-to-compression-oracles-on-the-web/
]]

---
-- @usage
-- nmap -sV -p 443 --script http-breach <target>
-- @output
-- PORT    STATE SERVICE REASON
-- 443/tcp open  https   syn-ack ttl 45
-- | http-breach:
-- |   VULNERABLE:
-- |   HTTP BREACH vulnerability
-- |     State: LIKELY VULNERABLE
-- |     IDs:  CVE:CVE-2013-3587
-- |       This web application might be affected by the BREACH attack. CRIME
-- |       is a compression side-channel attack against HTTPS. BREACH is based
-- |       on CRIME but attacks HTTP compression--the use of gzip or DEFLATE
-- |       data compression in the Content-Encoding header.
-- |
-- |       For a server to be vulnerable to BREACH it must:
-- |
-- |       1. Use HTTP-level compression
-- |       2. Reflect user-input in HTTP response bodies
-- |       3. Reflect a secret (such as a CSRF token) in HTTP response bodies
-- |
-- |       This script only checks for #1, but also confirms that the response is
-- |       successfully received with the Referer header set (some mitigations are
-- |       based on this header; see the qualys link).
-- |
-- |       To complete the test for BREACH, #2 and #3 must be identified. #2 can
-- |       be found with the "Input returned in response (reflected)" issue in Burp
-- |       Suite Professional's scanner. Whether those same requests return a secret
-- |       must be manually confirmed.
-- |
-- |     Disclosure date: 2013-09-11
-- |     Check results:
-- |       Host: example.com
-- |       Content-Encoding: gzip
-- |       Response code: 200
-- |       Request Referer: https://google.com/
-- |     References:
-- |       http://www.breachattack.com/
-- |_      https://blog.qualys.com/ssllabs/2013/08/07/defending-against-the-breach-attack
--
-- @xmloutput
-- <table key="CVE-2013-3587">
-- <elem key="title">HTTP BREACH vulnerability</elem>
-- <elem key="state">LIKELY VULNERABLE</elem>
-- <table key="ids">
-- <elem>CVE:CVE-2013-3587</elem>
-- </table>
-- <table key="description">
-- <elem>Make note that this is only have of the confirmation....&#xa;&#xa;This web application might be affected by the BREACH attack. CRIME&#xa;is a compression side-channel attack against HTTPS. BREACH is based&#xa;on CRIME but attacks HTTP compression-&#45;the use of gzip or DEFLATE&#xa;data compression in the Content-Encoding header.&#xa;&#xa;For a server to be vulnerable to BREACH it must:&#xa;&#xa;1. Use HTTP-level compression&#xa;2. Reflect user-input in HTTP response bodies&#xa;3. Reflect a secret (such as a CSRF token) in HTTP response bodies&#xa;&#xa;This script only checks for #1, but also confirms that the response is&#xa;successfully received with the Referer header set (some mitigations are&#xa;based on this header; see the Qualys link).&#xa;&#xa;To complete the test for BREACH, #2 and #3 must be identified. #2 can&#xa;be found with the &quot;Input returned in response (reflected)&quot; issue in Burp&#xa;Suite Professional&apos;s scanner. Whether those same requests return a secret&#xa;must be manually confirmed.&#xa;&#x9;&#x9;</elem>
-- </table>
-- <table key="dates">
-- <table key="disclosure">
-- <elem key="month">09</elem>
-- <elem key="day">11</elem>
-- <elem key="year">2013</elem>
-- </table>
-- </table>
-- <elem key="disclosure">2013-09-11</elem>
-- <table key="check_results">
-- <elem>Host: thecadencegroup.com</elem>
-- <elem>Content-Encoding: gzip</elem>
-- <elem>Response code: 200</elem>
-- <elem>Request Referer: https://google.com/</elem>
-- </table>
-- <table key="refs">
-- <elem>http://www.breachattack.com/</elem>
-- <elem>https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-3587</elem>
-- <elem>https://blog.qualys.com/ssllabs/2013/08/07/defending-against-the-breach-attack</elem>
-- </table>
-- </table>
-- @args http-breach.uri URI. Default: /
---
---
---
author = {"Jeffrey Stiles (@uthcr33p) <jeff()aerissecure com>"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "safe", "vuln"}

portrule = function(host, port)
  return shortport.http(host, port) and shortport.ssl(host, port)
end

action = function(host, port)
local uri = stdnse.get_script_args(SCRIPT_NAME..".uri") or '/'
	local hostname = stdnse.get_hostname(host)
	-- permit custom URI

	local options = {header={}}
	options["header"]["Referer"] = "https://google.com/"
	options["header"]["Connection"] = "Close"
	options["header"]["Accept-encoding"] = "gzip,deflate,compress"
	options["header"]["Accept"] = "text/*"

	stdnse.verbose("[%s] Sending GET request to '%s'", hostname, uri)
	local rsp = http.get(hostname, port, uri, options)

	if rsp == nil then
		stdnse.debug1("[%s]: Response is empty", hostname)
		return
	end

	if rsp.status == nil then
		stdnse.debug1("[%s] Error with request: %s", hostname, rsp["status-line"])
		return
	end

	if rsp.status ~= 200 then
		stdnse.debug1("[%s] Skipping, response code was %s, not 200", hostname, rsp.status)
		return
	end

	local encoding = rsp.header["content-encoding"]
	if encoding == nil then
		stdnse.debug1("[%s] Skipping, Content-Encoding header not present", hostname)
		return
	end

	local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
	local vuln = {
		title = 'HTTP BREACH attack',
		state = vulns.STATE.LIKELY_VULN,
		description = [[
This web application might be affected by the BREACH attack. CRIME
is a compression side-channel attack against HTTPS. BREACH is based
on CRIME but attacks HTTP compression--the use of gzip or DEFLATE
data compression in the Content-Encoding header.

For a server to be vulnerable to BREACH it must:

1. Use HTTP-level compression
2. Reflect user-input in HTTP response bodies
3. Reflect a secret (such as a CSRF token) in HTTP response bodies

This script only checks for #1, but also confirms that the response is
successfully received with the Referer header set (some mitigations are
based on this header; see the Qualys link).

To complete the test for BREACH, #2 and #3 must be verified. #2 can
be found with the "Input returned in response (reflected)" issue in Burp
Suite Professional's scanner. Whether those same requests return a secret
(#3) must be confirmed through manual review.
		]],
		IDS = {CVE = "CVE-2013-3587"},
		references = {
			"http://www.breachattack.com/",
			"https://blog.qualys.com/ssllabs/2013/08/07/defending-against-the-breach-attack",
			"https://blog.cloudflare.com/a-solution-to-compression-oracles-on-the-web/",
		},
		dates = {
			disclosure = {year = "2013", month = "09", day = "11"},
		},
		check_results = {
			string.format("Host: %s", hostname),
			string.format("Content-Encoding: %s", encoding),
			string.format("Response code: %s", rsp.status),
			string.format("Request Referer: %s", options["header"]["Referer"]),
		}
	}
	return vuln_report:make_output(vuln)
end
