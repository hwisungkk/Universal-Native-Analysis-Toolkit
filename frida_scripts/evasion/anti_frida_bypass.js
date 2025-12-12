/**
 * Anti-Frida Detection Bypass
 *
 * This script bypasses common Frida detection techniques:
 * - Named pipe detection (frida-*)
 * - Port scanning (Frida server on 27042)
 * - Library name checks (frida-agent, frida-gadget)
 * - Thread name detection
 * - File descriptor checks
 */

(function() {
    'use strict';

    console.log("[*] Anti-Frida Bypass loaded");

    // Bypass 1: Frida named pipe detection (/proc/self/fd/*, /proc/self/maps)
    if (Java.available) {
        Java.perform(function() {
            try {
                // Hook File operations
                var File = Java.use("java.io.File");

                File.exists.implementation = function() {
                    var path = this.getAbsolutePath();
                    if (path.indexOf("frida") !== -1 ||
                        path.indexOf("re.frida") !== -1 ||
                        path.indexOf("linjector") !== -1) {
                        console.log("[*] Blocked File.exists: " + path);
                        return false;
                    }
                    return this.exists.call(this);
                };

                File.canRead.implementation = function() {
                    var path = this.getAbsolutePath();
                    if (path.indexOf("frida") !== -1 ||
                        path.indexOf("re.frida") !== -1) {
                        console.log("[*] Blocked File.canRead: " + path);
                        return false;
                    }
                    return this.canRead.call(this);
                };

                console.log("[+] File API hooks installed");
            } catch (e) {
                console.log("[-] Failed to hook File: " + e);
            }

            try {
                // Hook Runtime.exec to prevent port scanning
                var Runtime = Java.use("java.lang.Runtime");
                Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
                    if (cmd.indexOf("frida") !== -1 ||
                        cmd.indexOf("27042") !== -1 ||
                        cmd.indexOf("netstat") !== -1 ||
                        cmd.indexOf("lsof") !== -1) {
                        console.log("[*] Blocked Runtime.exec: " + cmd);
                        throw Java.use("java.io.IOException").$new("Permission denied");
                    }
                    return this.exec.overload('java.lang.String').call(this, cmd);
                };

                Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmdarray) {
                    var cmd = cmdarray.join(" ");
                    if (cmd.indexOf("frida") !== -1 ||
                        cmd.indexOf("27042") !== -1) {
                        console.log("[*] Blocked Runtime.exec: " + cmd);
                        throw Java.use("java.io.IOException").$new("Permission denied");
                    }
                    return this.exec.overload('[Ljava.lang.String;').call(this, cmdarray);
                };

                console.log("[+] Runtime.exec hooks installed");
            } catch (e) {
                console.log("[-] Failed to hook Runtime.exec: " + e);
            }

            try {
                // Hook ProcessBuilder to prevent command execution
                var ProcessBuilder = Java.use("java.lang.ProcessBuilder");
                ProcessBuilder.start.implementation = function() {
                    var cmd = this.command();
                    var cmdStr = cmd.toString();
                    if (cmdStr.indexOf("frida") !== -1 ||
                        cmdStr.indexOf("27042") !== -1) {
                        console.log("[*] Blocked ProcessBuilder.start: " + cmdStr);
                        throw Java.use("java.io.IOException").$new("Permission denied");
                    }
                    return this.start.call(this);
                };

                console.log("[+] ProcessBuilder hooks installed");
            } catch (e) {
                console.log("[-] Failed to hook ProcessBuilder: " + e);
            }
        });
    }

    // Bypass 2: Native library name checks
    try {
        var fopen = Module.findExportByName(null, 'fopen');
        if (fopen) {
            Interceptor.attach(fopen, {
                onEnter: function(args) {
                    var path = Memory.readUtf8String(args[0]);
                    if (path) {
                        // Block access to frida-related files
                        if (path.indexOf("frida") !== -1 ||
                            path.indexOf("re.frida") !== -1 ||
                            path.indexOf("/proc/") === 0 && (
                                path.indexOf("/maps") !== -1 ||
                                path.indexOf("/task") !== -1 ||
                                path.indexOf("/fd/") !== -1
                            )) {
                            console.log("[*] Blocked fopen: " + path);
                            args[0] = Memory.allocUtf8String("/dev/null");
                        }
                    }
                }
            });
            console.log("[+] fopen hook installed");
        }
    } catch (e) {
        console.log("[-] Failed to hook fopen: " + e);
    }

    // Bypass 3: strstr / strncmp checks for "frida"
    try {
        var strstr = Module.findExportByName(null, 'strstr');
        if (strstr) {
            Interceptor.attach(strstr, {
                onEnter: function(args) {
                    this.needle = Memory.readUtf8String(args[1]);
                },
                onLeave: function(retval) {
                    if (this.needle && (
                        this.needle.indexOf("frida") !== -1 ||
                        this.needle.indexOf("FRIDA") !== -1 ||
                        this.needle.indexOf("Frida") !== -1
                    )) {
                        console.log("[*] Blocked strstr for: " + this.needle);
                        retval.replace(ptr(0));
                    }
                }
            });
            console.log("[+] strstr hook installed");
        }
    } catch (e) {
        console.log("[-] Failed to hook strstr: " + e);
    }

    try {
        var strcmp = Module.findExportByName(null, 'strcmp');
        if (strcmp) {
            Interceptor.attach(strcmp, {
                onEnter: function(args) {
                    this.str1 = Memory.readUtf8String(args[0]);
                    this.str2 = Memory.readUtf8String(args[1]);
                },
                onLeave: function(retval) {
                    if ((this.str1 && this.str1.toLowerCase().indexOf("frida") !== -1) ||
                        (this.str2 && this.str2.toLowerCase().indexOf("frida") !== -1)) {
                        console.log("[*] Blocked strcmp for frida-related string");
                        retval.replace(ptr(1)); // Not equal
                    }
                }
            });
            console.log("[+] strcmp hook installed");
        }
    } catch (e) {
        console.log("[-] Failed to hook strcmp: " + e);
    }

    // Bypass 4: Port scanning detection (TCP connect to 27042)
    try {
        var connect = Module.findExportByName(null, 'connect');
        if (connect) {
            Interceptor.attach(connect, {
                onEnter: function(args) {
                    try {
                        var sockaddr = args[1];
                        // Check if it's IPv4
                        var sa_family = Memory.readU16(sockaddr);
                        if (sa_family === 2) { // AF_INET
                            var port = (Memory.readU8(sockaddr.add(2)) << 8) | Memory.readU8(sockaddr.add(3));
                            if (port === 27042 || port === 27043) {
                                console.log("[*] Blocked connect to Frida port: " + port);
                                this.block = true;
                            }
                        }
                    } catch (e) {}
                },
                onLeave: function(retval) {
                    if (this.block) {
                        retval.replace(ptr(-1));
                    }
                }
            });
            console.log("[+] connect hook installed");
        }
    } catch (e) {
        console.log("[-] Failed to hook connect: " + e);
    }

    // Bypass 5: Thread name detection
    try {
        var pthread_getname_np = Module.findExportByName(null, 'pthread_getname_np');
        if (pthread_getname_np) {
            Interceptor.attach(pthread_getname_np, {
                onLeave: function(retval) {
                    try {
                        var name = Memory.readUtf8String(arguments[1]);
                        if (name && name.toLowerCase().indexOf("frida") !== -1) {
                            console.log("[*] Hiding Frida thread name: " + name);
                            Memory.writeUtf8String(arguments[1], "Thread-" + Math.floor(Math.random() * 1000));
                        }
                    } catch (e) {}
                }
            });
            console.log("[+] pthread_getname_np hook installed");
        }
    } catch (e) {
        console.log("[-] Failed to hook pthread_getname_np: " + e);
    }

    // Bypass 6: /proc/self/status detection
    try {
        var open = Module.findExportByName(null, 'open');
        if (open) {
            Interceptor.attach(open, {
                onEnter: function(args) {
                    var path = Memory.readUtf8String(args[0]);
                    if (path && (
                        path === "/proc/self/status" ||
                        path === "/proc/self/maps" ||
                        path === "/proc/self/task"
                    )) {
                        console.log("[*] Redirecting open: " + path);
                        // Redirect to /dev/null to hide Frida artifacts
                        args[0] = Memory.allocUtf8String("/dev/null");
                    }
                }
            });
            console.log("[+] open hook installed");
        }
    } catch (e) {
        console.log("[-] Failed to hook open: " + e);
    }

    console.log("[*] Anti-Frida bypass complete!");

    send({
        type: 'evasion',
        module: 'anti_frida',
        status: 'active',
        message: 'Anti-Frida detection bypass enabled'
    });

})();
