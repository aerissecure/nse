local coroutine = require "coroutine"
local dns = require "dns"
local io = require "io"
local math = require "math"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local target = require "target"

description = [[
Attempts to enumerate DNS hostnames by brute force guessing of common
subdomains. With the <code>dns-brute.srv</code> argument, dns-brute will also
try to enumerate common DNS SRV records.

The main difference between dns-brute2 and the original is the ability to
specify a resolver list. Past a few threads, using a single resolver may
result in rate limiting and misses from the system's default resolver. The
resolver list allows each thread to use a different resolver.

Since this script will run concurrently for many hosts, once a resolver is
used for a thread, it is taken out of rotation such that each resolver is
only used once. Once all resolvers are used, remaining threads will fall back to the
system resolver.

Because the list of resolvers is potentially stale or out-of-date, an option
(checkresolvers) is included to require a single successfull resolution
from the resolver before including it in the pool.

The number of resolvers from the list that will be used is determined by the
number of hosts to be scanned and the number of threads. The maxresolvers
option can be used so that no resolvers need to be checked beyond what will
be used for the scan.

Note that the original script strips hosts down to their root domain before
performing the scan. If you want to scan subdomains of a subdomain, the
script may need to be adjusted.
]]

-- 2016-02-21

---
-- @usage
-- nmap --script dns-brute2 --script-args dns-brute.threads=10,dns-brute.hostlist=./vhosts.lst,dns-brute.maxhosts=1000,dns-brute.resolverlist=./resolvers.lst,dns-brute.checkresolvers=true,dns-brute.maxresolvers=50  -sn -Pn -d

-- nmap --script dns-brute2 --script-args dns-brute.domain=foo.com,dns-brute.threads=6,dns-brute.hostlist=./hostfile.txt,newtargets -sS -p 80
-- nmap --script dns-brute www.foo.com
-- @args dns-brute.hostlist The filename of a list of host strings to try.
--                          Defaults to "nselib/data/vhosts-default.lst"
-- @args dns-brute.threads  Thread to use (default 5).
-- @args dns-brute.srv      Perform lookup for SRV records
-- @args dns-brute.srvlist  The filename of a list of SRV records to try.
--                          Defaults to "nselib/data/dns-srv-names"
-- @args dns-brute.domain   Domain name to brute force if no host is specified

-- @args dns-brute.maxhosts       Limit the number of hosts to try. Default list is
--                                sorted by frequency so common names are tried first.
-- @args dns-brute.resolverlist   The filename of a list of dns resolvers to try.
-- @args dns-brute.checkresolvers Perform a check to ensure each resolver is working
--                                before using it (takes more time)
-- @args dns-brute.maxresolvers   Limit the number of resolvers to use from the
--                                provided list. Number of supplied hosts times the
--                                number of threads is the most efficient value.
-- @args dns-brute.stripdomain    Strip subdomains from scanned domains so that children
--                                of only the primary domain are found. E.g. scan
--                                *.example.com when sub.example.com is provided, instead
--                                of *.sub.example.com
-- @output
-- Pre-scan script results:
-- | dns-brute2:
-- |   DNS Brute-force hostnames
-- |     www.foo.com - 127.0.0.1
-- |     mail.foo.com - 127.0.0.2
-- |     blog.foo.com - 127.0.1.3
-- |     ns1.foo.com - 127.0.0.4
-- |_    admin.foo.com - 127.0.0.5
-- @xmloutput
-- <table key="DNS Brute-force hostnames">
--   <table>
--     <elem key="address">127.0.0.1</elem>
--     <elem key="hostname">www.foo.com</elem>
--   </table>
--   <table>
--     <elem key="address">127.0.0.2</elem>
--     <elem key="hostname">mail.foo.com</elem>
--   </table>
--   <table>
--     <elem key="address">127.0.1.3</elem>
--     <elem key="hostname">blog.foo.com</elem>
--   </table>
--   <table>
--     <elem key="address">127.0.0.4</elem>
--     <elem key="hostname">ns1.foo.com</elem>
--   </table>
--   <table>
--     <elem key="address">127.0.0.5</elem>
--     <elem key="hostname">admin.foo.com</elem>
--   </table>
-- </table>
-- <table key="SRV results"></table>

author = "Jeffrey Stiles (original dns-brute script by Cirrus)"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"intrusive", "discovery"}

-- check if resolvers is working
local function resolver_ok(resolver)
  if not stdnse.get_script_args('dns-brute.checkresolvers') then
    return true
  end
  local status, result = dns.query("example.com", {dtype="A",retAll=true,host=resolver})
  return status and result or false
end

-- add the resolvers to the registry
local function get_resolvers()
  -- check if resolvers have already been set
  if nmap.registry.bruteresolvers then
    return
  end

  -- set local resolver
  local resolvers = nmap.get_dns_servers()
  if resolvers and resolvers[1] then
    nmap.registry.bruteresolver = resolvers[1]
    stdnse.debug1("Added local resolver: %s", resolvers[1])
  end

  -- set and fill public resolvers array
  nmap.registry.bruteresolvers = {}

  -- First look for dns-brute.resolverlist
  local fileName = stdnse.get_script_args('dns-brute.resolverlist')
  -- Check fetchfile locations, then relative paths
  local commFile = (fileName and nmap.fetchfile(fileName)) or fileName
  -- Finally, fall back to vhosts-default.lst
  commFile = commFile or nmap.fetchfile("nselib/data/resolvers.lst")

  if not commFile then
    -- need to adjust since can't exit from here
    stdnse.debug1("Cannot find resolverlist file. Local resolver will be used if possible")
    return
  end

  local max_resolvers = tonumber( stdnse.get_script_args('dns-brute.maxresolvers') )
  local n = 1
  for l in io.lines(commFile) do
    if max_resolvers and n > max_resolvers then
      stdnse.debug1("maxresolvers reached: %s", max_resolvers)
      break
    end

    if resolver_ok(l) and not l:match("^#") then
      n = n + 1
      -- using table.insert treats table like an array, where the keys are
      -- ints and the values are what you're inserting. To remove values, you
      -- have to do table.remove(tablename, id) where id is its index.
      -- doing it this way keeps everything in order.
      table.insert(nmap.registry.bruteresolvers, l)
      stdnse.debug1("Added public resolver: %s", l)
    end
  end
end

prerule = function()
  get_resolvers()
  if not stdnse.get_script_args("dns-brute.domain") then
    stdnse.debug1("Skipping '%s' %s, 'dns-brute.domain' argument is missing.", SCRIPT_NAME, SCRIPT_TYPE)
    return false
  end
  return true
end

hostrule = function(host)
  return true
end

local function guess_domain(host)
  local name

  name = stdnse.get_hostname(host)
  if name and name ~= host.ip then
    if stdnse.get_script_args('dns-brute.stripdomain') then
      return string.match(name, "%.([^.]+%..+)%.?$") or string.match(name, "^([^.]+%.[^.]+)%.?$")
    end
    return name
  else
    return nil
  end
end

-- Single DNS lookup, returning all results. dtype should be e.g. "A", "AAAA".
local function resolve(host, dtype, resolver)
  local status, result = dns.query(host, {dtype=dtype,retAll=true,host=resolver})
  if not status and result == "No Answers" then
    stdnse.debug1("No answer from %s for host %s (rate limited?)", resolver, host)
  end
  return status and result or false
end

local function array_iter(array, i, j)
  return coroutine.wrap(function ()
    while i <= j do
      coroutine.yield(array[i])
      i = i + 1
    end
  end)
end

local function thread_main(domainname, results, name_iter, resolver)
  local condvar = nmap.condvar( results )
  for name in name_iter do
    for _, dtype in ipairs({"A", "AAAA"}) do
      local res = resolve(name..'.'..domainname, dtype, resolver)
      if(res) then
        for _,addr in ipairs(res) do
          local hostn = name..'.'..domainname
          if target.ALLOW_NEW_TARGETS then
            stdnse.debug1("Added target: "..hostn)
            local status,err = target.add(hostn)
          end
          stdnse.debug1("Hostname: "..hostn.." IP: "..addr)
          local record = { hostname=hostn, address=addr }
          setmetatable(record, {
            __tostring = function(t)
              return string.format("%s - %s", t.hostname, t.address)
            end
          })
          results[#results+1] = record
        end
      end
    end
  end
  condvar("signal")
end

local function srv_main(domainname, srvresults, srv_iter, resolver)
  local condvar = nmap.condvar( srvresults )
  for name in srv_iter do
    local res = resolve(name..'.'..domainname, "SRV", resolver)
    if(res) then
      for _,addr in ipairs(res) do
        local hostn = name..'.'..domainname
        addr = stdnse.strsplit(":",addr)
        for _, dtype in ipairs({"A", "AAAA"}) do
          local srvres = resolve(addr[4], dtype)
          if(srvres) then
            for srvhost,srvip in ipairs(srvres) do
              if target.ALLOW_NEW_TARGETS then
                stdnse.debug1("Added target: "..srvip)
                local status,err = target.add(srvip)
              end
              stdnse.debug1("Hostname: "..hostn.." IP: "..srvip)
              local record = { hostname=hostn, address=srvip }
              setmetatable(record, {
                __tostring = function(t)
                  return string.format("%s - %s", t.hostname, t.address)
                end
              })
              srvresults[#srvresults+1] = record
            end
          end
        end
      end
    end
  end
  condvar("signal")
end

action = function(host)
  local domainname = stdnse.get_script_args('dns-brute.domain')
  if not domainname then
    domainname = guess_domain(host)
  end
  if not domainname then
    return string.format("Can't guess domain of \"%s\"; use %s.domain script argument.", stdnse.get_hostname(host), SCRIPT_NAME)
  end

  if not nmap.registry.bruteddomains then
    nmap.registry.bruteddomains = {}
  end

  if nmap.registry.bruteddomains[domainname] then
    stdnse.debug1("Skipping already-bruted domain %s", domainname)
    return nil
  end

  nmap.registry.bruteddomains[domainname] = true
  stdnse.debug1("Starting dns-brute at: "..domainname)
  local max_threads = tonumber( stdnse.get_script_args('dns-brute.threads') ) or 5
  local dosrv = stdnse.get_script_args("dns-brute.srv") or false
  stdnse.debug1("THREADS: "..max_threads)
  -- First look for dns-brute.hostlist
  local fileName = stdnse.get_script_args('dns-brute.hostlist')
  -- Check fetchfile locations, then relative paths
  local commFile = (fileName and nmap.fetchfile(fileName)) or fileName
  -- Finally, fall back to vhosts-default.lst
  commFile = commFile or nmap.fetchfile("nselib/data/vhosts-default.lst")
  local max_hosts = tonumber( stdnse.get_script_args('dns-brute.maxhosts') )

  if not commFile then
    stdnse.debug1("Cannot find hostlist file, quitting")
    return
  end

  local hostlist = {}
  local n = 0
  for l in io.lines(commFile) do
    if not l:match("^#") then
      n = n + 1
      -- limit to max number of hosts
      if max_hosts and n > max_hosts then
        break
      end

      if l:find("%s") then
        -- each line has a count and is of form "subdomainname 3499238"
        table.insert(l:sub(0, l:find(" ")-1))
      else
        -- if no space if found, just add the line
        table.insert(hostlist, l)
      end
    end
  end

  local threads, results, srvresults = {}, {}, {}
  local condvar = nmap.condvar( results )
  local i = 1
  local howmany = math.floor(#hostlist/max_threads)+1
  stdnse.debug1("Hosts per thread: "..howmany)

  repeat
    local j = math.min(i+howmany, #hostlist)

    -- use resolver from list or local resolver
    local resolver = table.remove(nmap.registry.bruteresolvers, 1)
    if resolver == nil then
      if nmap.registry.bruteresolver then
        resolver = nmap.registry.bruteresolver
      else
        stdnse.debug1("Public and local resolvers are missing, quitting")
        return
      end
    end

    stdnse.debug1("Using resolver: %s", resolver)

    local name_iter = array_iter(hostlist, i, j)
    threads[stdnse.new_thread(thread_main, domainname, results, name_iter, resolver)] = true
    i = j+1
  until i > #hostlist
  local done
  -- wait for all threads to finish
  while( not(done) ) do
    done = true
    for thread in pairs(threads) do
      if (coroutine.status(thread) ~= "dead") then done = false end
    end
    if ( not(done) ) then
      condvar("wait")
    end
  end

  if(dosrv) then
    -- First look for dns-brute.srvlist
    fileName = stdnse.get_script_args('dns-brute.srvlist')
    -- Check fetchfile locations, then relative paths
    commFile = (fileName and nmap.fetchfile(fileName)) or fileName
    -- Finally, fall back to dns-srv-names
    commFile = commFile or nmap.fetchfile("nselib/data/dns-srv-names")
    local srvlist = {}
    if commFile then
      for l in io.lines(commFile) do
        if not l:match("#!comment:") then
          table.insert(srvlist, l)
        end
      end

      i = 1
      threads = {}
      howmany = math.floor(#srvlist/max_threads)+1
      condvar = nmap.condvar( srvresults )
      stdnse.debug1("SRV's per thread: "..howmany)
      repeat
        local j = math.min(i+howmany, #srvlist)
        local name_iter = array_iter(srvlist, i, j)
        threads[stdnse.new_thread(srv_main, domainname, srvresults, name_iter)] = true
        i = j+1
      until i > #srvlist
      local done
      -- wait for all threads to finish
      while( not(done) ) do
        done = true
        for thread in pairs(threads) do
          if (coroutine.status(thread) ~= "dead") then done = false end
        end
        if ( not(done) ) then
          condvar("wait")
        end
      end
    else
      stdnse.debug1("Cannot find srvlist file, skipping")
    end
  end

  local response = stdnse.output_table()
  if(#results==0) then
    setmetatable(results, { __tostring = function(t) return "No results." end })
  end
  response["DNS Brute-force hostnames"] = results
  if(dosrv) then
    if(#srvresults==0) then
      setmetatable(srvresults, { __tostring = function(t) return "No results." end })
    end
    response["SRV results"] = srvresults
  end
  return response
end

