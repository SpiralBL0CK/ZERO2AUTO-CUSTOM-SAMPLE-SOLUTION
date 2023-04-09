from __future__ import print_function
import frida
import sys
import time

def on_message(message, data):
    print("[%s] => %s" % (message, data))

def main(target_process):
    device = frida.get_local_device()
    pid = device.spawn(target_process)
    session = device.attach(pid)
    session.enable_child_gating()

    script = session.create_script("""

    function instrumentInternetOpenUrl(opts) {
        var pInternetOpenUrl = opts.unicode ? Module.findExportByName("wininet.dll", "InternetOpenUrlW")
                                            : Module.findExportByName("wininet.dll", "InternetOpenUrlA");
        if(null == pInternetOpenUrl)
            return 0;

        Interceptor.attach(pInternetOpenUrl, {
            onEnter: function(args) {
                if (args[1].readUtf8String() == 'cruloader'){
                var new_url = 'http://127.0.0.1:8000/abc.txt\\0';
                var url_string = opts.unicode ? Memory.allocUtf16String(new_url) : Memory.allocUtf8String(new_url);
                var old_url_addr = this.context.sp.add(8);
                Memory.copy(args[1], url_string, new_url.length)
                } 
                var url = opts.unicode ? args[1].readUtf16String() : args[1].readUtf8String();

                send({
                    'hook': 'InternetOpenUrl',
                    'url': url,
                    'arg': args[1],
                });
            },
            onLeave: function (retval) {
            send({'retval:' : this.lastError});
        }
        });
        return 1;
    }

    function instrumentGetAddrInfo(opts) {
        if(opts.ex) {
            var pGetAddrInfo = opts.unicode ? Module.findExportByName("ws2_32.dll", "GetAddrInfoExW")
                                            : Module.findExportByName("ws2_32.dll", "GetAddrInfoExA");
        } else {
            var pGetAddrInfo = opts.unicode ? Module.findExportByName("ws2_32.dll", "GetAddrInfoW")
                                            : Module.findExportByName("ws2_32.dll", "getaddrinfo");
        }

        if(null == pGetAddrInfo)
            return 0;

        Interceptor.attach(pGetAddrInfo, {
            onEnter: function(args) {
                var domain = opts.unicode ? args[0].readUtf16String() : args[0].readUtf8String();
                send({
                    'hook': 'GetAddrInfo',
                    'domain': domain
                });
            }
        });
        return 1;
    }


    var InternetOpenUrl_Instrumented = 0;
    var GetAddrInfo_Instrumented = 0;

    /*
    HMODULE LoadLibraryW(
      LPCWSTR lpLibFileName
    );
    */
    function instrumentLoadLibrary(opts) {
        var pLoadLibrary = opts.unicode ? Module.findExportByName(null, "LoadLibraryW")
                                        : Module.findExportByName(null, "LoadLibraryA")
        Interceptor.attach(pLoadLibrary, {
            onEnter: function(args) {
                this.wininet = 0;
                this.ws2_32  = 0;
                var libName = (opts.unicode ? args[0].readUtf16String() : args[0].readUtf8String()).toLowerCase();
                if(libName.startsWith("wininet"))
                    this.wininet = 1;
                else if(libName.startsWith("ws2_32"))
                    this.ws2_32 = 1;
            },
            onLeave: function(retval) {
                if(this.wininet == 1 && !InternetOpenUrl_Instrumented) {
                    instrumentInternetOpenUrl({unicode: 0});
                    instrumentInternetOpenUrl({unicode: 1});
                } else if(this.ws2_32 == 1 && !GetAddrInfo_Instrumented) {
                    instrumentGetAddrInfo({unicode: 0, ex: 0});
                    instrumentGetAddrInfo({unicode: 1, ex: 0});
                    instrumentGetAddrInfo({unicode: 0, ex: 1});
                    instrumentGetAddrInfo({unicode: 1, ex: 1});
                }
            }
        });
    }

    InternetOpenUrl_Instrumented = (instrumentInternetOpenUrl({unicode: 0}) && 
                                    instrumentInternetOpenUrl({unicode: 1}));

    GetAddrInfo_Instrumented = (instrumentGetAddrInfo({unicode: 0, ex: 0}) && 
                                instrumentGetAddrInfo({unicode: 1, ex: 0}) && 
                                instrumentGetAddrInfo({unicode: 0, ex: 1}) && 
                                instrumentGetAddrInfo({unicode: 1, ex: 1}));

    if(!InternetOpenUrl_Instrumented || !GetAddrInfo_Instrumented) {        // (wininet.dll | ws2_32.dll) not imported yet
        instrumentLoadLibrary({unicode: 0});
        instrumentLoadLibrary({unicode: 1});
    }
    """)
    
    script.on('message', on_message)
    script.load()
    device.resume(pid)
    print("[!] Ctrl+D on UNIX, Ctrl+Z on Windows/cmd.exe to detach from instrumented program.\n\n")
    sys.stdin.read()
    session.detach()

if __name__ == '__main__':
    #    if len(sys.argv) != 2:
    #        print("Usage: %s <process path>" % __file__)
    #        sys.exit(1)
    
    #target_process = sys.argv[1]
    target_process = "C:\\Users\\Vlad\\Desktop\\stage2_challenge_mal_analysis.dll"
    main(target_process)


    