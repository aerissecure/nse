description = [[
This script uses PhantomJS to connect to all dicovered HTTP services and save
a rendered image of the website to a file and print a snippet of the visible
text on the rendered page. An HTML file is produced to display all captured
images and provide links to their targets

There is a 'textonly' option to save only the rendered text without the image
file. By default, images are base64 encoded and embedded in the HTML file.
However, the 'files' option can be used to output the images to separate files
that the HTML file will reference. The 'prefix' option allows all output files
to be prefixed in order to avoid conflicts.

If you encounter errors running this script on a headless system, you can use
the 'headless' option to pass the correct environment variables.

A common use case for this script is to quickly identify what is running on all
HTTP servers discovered during a scan so that interesting targets can quickly
be identified for further investigation.

This script relies on the PhantomJS binary. This application should be
downloaded from http://phantomjs.org/ and placed on the system path.
]]

---
-- @args http-screenshot.textonly Output only rendered text
-- @args http-screenshot.files Output individual images files
-- @args http-screenshot.prefix Prefix to use for naming output files
--
-- @usage
-- nmap --script http-screenshot <target>
-- nmap --script http-screenshot --script-args http-screenshot.textonly <target>
-- nmap --script http-screenshot --script-args http-screenshot.files <target>
-- nmap --script http-screenshot --script-args http-screenshot.prefix="pre" <target>
-- nmap --script http-screenshot --script-args http-screenshot.headless
--
-- @output
-- 443/tcp open  https   syn-ack
-- | http-screenshot:
-- |   filename: http-screenshot_aerissecure.com_443.png
-- |_  text: Home Services Resources Aeris Labs Blog About Contact Compli...


-- HTTP screenshot script
-- rev 1.1 (2016-08-23)
-- Original NASL script by Jeffrey Stiles (@uthcr33p)(jeff@aerissecure.com)

categories = {"default", "discovery", "safe"}
author = "Jeffrey Stiles"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

local base64 = require "base64"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"


local prefix = stdnse.get_script_args(SCRIPT_NAME .. ".prefix") or ""
if prefix ~= "" then
    prefix = prefix .. "-"
end

-- JS script to be called by PhantomJS
local phantomjs_script = [[
"use strict";
var page = require('webpage').create(),
    system = require('system'),
    address, output;

address = system.args[1];
page.viewportSize = { width: 1024, height: 600 };
page.settings.resourceTimeout = 20000; // Allow time for slow resources

var pageTimeout = 30000;

var requests = [];
var waitTime = 0;

page.onResourceRequested = function(requestData, networkRequest) {
    requests.push(requestData.id);
};

page.onResourceReceived = function(response) {
    var index = requests.indexOf(response.id);
    waitTime = 0; // reset waitTime when resource is received
    requests.splice(index, 1);
};

page.onResourceError = function(resourceError) {
    var index = requests.indexOf(resourceError.id);
    requests.splice(index, 1);
}

page.onResourceTimeout = function(request) {
    var index = requests.indexOf(request.id);
    requests.splice(index, 1);
};

page.open(address, function (status) {
    if (status !== 'success' || system.args.length > 3) {
        // Unable to load the address, or too many args
        console.log("PhantomJS: page.open failed");
        phantom.exit(1);
    }

    // Wait until all network requests finish
    var interval = setInterval(function () {
        waitTime += 3000;
        // exit if pageTimeout is reached
        if (waitTime > pageTimeout) {
            console.log("error rendering output, pageTimeout reached: " + pageTimeout)
            phantom.exit();
        }

        if (requests.length === 0) {
            clearInterval(interval);

            if (system.args.length === 2) {
                console.log(page.plainText);
                phantom.exit();
            }
            if (system.args.length == 3) {
                output = system.args[2];
                page.render(output);
                console.log(page.plainText);
                phantom.exit();
            }
        }
    }, 3000); // Wait to finish loading
});
]]

local img_html = [[
<a href='%s' target=_blank style='font-size:x-large'>
%s
</a>
<br>
<img src='%s' width=400 border=1 style='max-width:1024; margin-top:5px;'
 onclick='this.setAttribute("width", this.getAttribute("width") === "400" ? "100%%" : "400")' />
<hr style="margin:20px 0 20px 0">
]]

--- References or embeds the image within index.html
local index_image = function(imgfile, url)
    local indexfile = string.format("%sindex.html", prefix)
    nmap.registry[SCRIPT_NAME].indexfile = indexfile

    stdnse.verbose("adding %s to index file %s", imgfile, indexfile)

    local index = io.open(indexfile, "a")

    local src
    if stdnse.get_script_args(SCRIPT_NAME .. '.files') then
        src = imgfile
    else -- embed
        local file = io.open(imgfile, "r")
        local data = file:read("*a")
        file:close()

        local b64data = base64.enc(data)
        src = string.format("data:image/png;base64,%s", b64data)
        -- Delete image file
        stdnse.verbose("deleting embeded image file %s", imgfile)
        os.remove(imgfile)
    end
    index:write(string.format(img_html, url, url, src))
    index:close()

    return indexfile, imgfile
end

prerule = function()
    -- Make nmap.registry[SCRIPT_NAME] always available
    nmap.registry[SCRIPT_NAME] = {}
    -- Check if 'phantomjs' is on the path
    local cmd = "command -v phantomjs >/dev/null 2>&1"
    local ret = os.execute(cmd)
    if ret then
        nmap.registry[SCRIPT_NAME].cmd = true
    else
        stdnse.verbose("aborting, phantomjs not on path. Download from http://phantomjs.org/")
        nmap.registry[SCRIPT_NAME].cmd = false
        return false
    end
    -- Create the temporary PhantomJS script
    local pjsfile = os.tmpname()
    local file = io.open(pjsfile, "w")
    file:write(phantomjs_script)
    file:close()
    -- Save file location for use in portrule
    nmap.registry[SCRIPT_NAME].pjsfile = pjsfile
    -- Don't call action
    return false
end

postrule = function()
    -- Clean up the temporary PhantomJS script
    if nmap.registry[SCRIPT_NAME].pjsfile then
        stdnse.verbose("cleaning up %s", nmap.registry[SCRIPT_NAME].pjsfile)
        os.remove(nmap.registry[SCRIPT_NAME].pjsfile)
    end
    if nmap.registry[SCRIPT_NAME].indexfile then
        stdnse.verbose("image index file is %s", nmap.registry[SCRIPT_NAME].indexfile)
    end
    -- Don't call action
    return false
end

portrule = function(host, port)
    if not nmap.registry[SCRIPT_NAME].cmd then
        -- 'phantomjs' not on path
        return false
    end
    return shortport.http(host, port)
end

action = function(host, port)
    local proto = "http"
    if port.version.service_tunnel == "ssl" or string.find(port.service, "https") then
        proto = "https"
    end

    -- Use target provided to nmap if it is not an IP, otherwise use the IP
    local target = host.targetname or host.ip
    local url = string.format("%s://%s:%s", proto, target, port.number)
    local filename = string.format("%shttp-screenshot_%s_%s.png", prefix, target, port.number)
    if stdnse.get_script_args(SCRIPT_NAME .. '.textonly') then
        filename = ""
    end

    stdnse.verbose("rendering html for %s", target)

    local pjsfile = nmap.registry[SCRIPT_NAME].pjsfile

    local cmd
    if stdnse.get_script_args(SCRIPT_NAME .. '.headless') then
        -- create XDG_RUNTIME_DIR, accessible only by user
        local tmpdir = os.tmpname()
        os.remove(tmpdir)
        os.execute("mkdir -m 700 " .. tmpdir)
        cmd = string.format("XDG_RUNTIME_DIR=\"%s\" QT_QPA_PLATFORM=offscreen phantomjs --ignore-ssl-errors=true %s %s %s", tmpdir, pjsfile, url, filename)
    else
        cmd = string.format("phantomjs --ignore-ssl-errors=true %s %s %s", pjsfile, url, filename)
    end

    local file = io.popen(cmd, 'r')
    if file == nil then
        return stdnse.format_output(false, "error reading reading output")
    end

    local text = file:read("*a")
    -- Trim leading/trailing white space
    text = text:match("^%s*(.-)%s*$"):gsub("%s+", " ")
    if filename == "" and text == nil then
        return stdnse.format_output(false, "error reading rendered text")
    end

    -- Write to index file if image is rendered
    local indexfile, imgfile
    if stdnse.get_script_args(SCRIPT_NAME .. '.textonly') == nil then
        indexfile, imgfile = index_image(filename, url)
    end

    local output = stdnse.output_table()
    local output_str = ""

    if stdnse.get_script_args(SCRIPT_NAME .. '.textonly') == nil then
        if stdnse.get_script_args(SCRIPT_NAME .. '.embed') ~= nil then
            output.filename = indexfile
        else
            output.filename = imgfile
        end
        output_str = string.format("\n  filename: %s", output.filename)
    end

    output.text = text
    output_str = output_str .. string.format("\n  text: %s...\n", string.sub(text, 1, 60))

    return output, output_str
end
