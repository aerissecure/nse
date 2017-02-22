NSE
===

A collection of Nmap scripts.

Installation
------------

1. Download the script file and place it in the nmap script directory: `/usr/share/nmap/scripts/`
2. Update the scripts database by running: `sudo nmap --script-updatedb`

Script Index
------------


### http-screenshot

Take a screenshot of discovered HTTP(S) services using PhantomJS. Requires at least Nmap version 7.0.


### http-sec-headers

Evaluate the security of the response headers received from a request to the web server root folder. Requires at least Nmap version 7.0.


### dns-brute2

A fork of the `dns-brute` script included with nmap which attempts to enumerate hostnames by brute force guessing common subdomains. This version allows a list of resolvers to be provided so that each thread can query a separate DNS server and avoid potential rate limits.

All additional options:

- `dns-brute.maxhosts`: Limit the number of hosts to try. Default list is sorted by frequency so common names are tried first.
- `dns-brute.resolverlist`: The filename of a list of dns resolvers to try.
- `dns-brute.checkresolvers`: Perform a check to ensure each resolver is working before using it (takes more time)
- `dns-brute.maxresolvers`: Limit the number of resolvers to use from the provided list. Number of supplied hosts times the number of threads is the most efficient value.
