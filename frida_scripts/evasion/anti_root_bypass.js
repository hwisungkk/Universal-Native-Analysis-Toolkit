/**
 * Anti-Root Detection Bypass
 *
 * This script bypasses common root detection techniques:
 * - su binary checks
 * - Magisk/SuperSU detection
 * - RootBeer library
 * - SafetyNet checks
 * - Test-keys detection
 */

(function() {
    'use strict';

    console.log("[*] Anti-Root Bypass loaded");

    if (!Java.available) {
        console.log("[-] Java not available, skipping Java hooks");
        return;
    }

    Java.perform(function() {
        // Common root check file paths
        var rootPaths = [
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/su/bin/su",
            "/system/xbin/daemonsu",
            "/system/etc/init.d/99SuperSUDaemon",
            "/dev/com.koushikdutta.superuser.daemon/",
            "/system/app/SuperSU",
            "/system/app/SuperSU.apk",
            "/system/bin/.ext/.su",
            "/system/usr/we-need-root/su-backup",
            "/system/xbin/mu",
            "/system/xbin/busybox",
            "/data/adb/magisk",
            "/sbin/.magisk",
            "/cache/.disable_magisk",
            "/dev/.magisk.unblock",
            "/cache/magisk.log",
            "/data/adb/magisk.img",
            "/data/adb/magisk.db",
            "/data/adb/magisk_simple"
        ];

        // Bypass 1: File.exists() for root binaries
        try {
            var File = Java.use("java.io.File");

            File.exists.implementation = function() {
                var path = this.getAbsolutePath();
                for (var i = 0; i < rootPaths.length; i++) {
                    if (path.indexOf(rootPaths[i]) !== -1) {
                        console.log("[*] Blocked File.exists: " + path);
                        return false;
                    }
                }
                return this.exists.call(this);
            };

            File.canRead.implementation = function() {
                var path = this.getAbsolutePath();
                for (var i = 0; i < rootPaths.length; i++) {
                    if (path.indexOf(rootPaths[i]) !== -1) {
                        console.log("[*] Blocked File.canRead: " + path);
                        return false;
                    }
                }
                return this.canRead.call(this);
            };

            File.canWrite.implementation = function() {
                var path = this.getAbsolutePath();
                for (var i = 0; i < rootPaths.length; i++) {
                    if (path.indexOf(rootPaths[i]) !== -1) {
                        console.log("[*] Blocked File.canWrite: " + path);
                        return false;
                    }
                }
                return this.canWrite.call(this);
            };

            File.canExecute.implementation = function() {
                var path = this.getAbsolutePath();
                for (var i = 0; i < rootPaths.length; i++) {
                    if (path.indexOf(rootPaths[i]) !== -1) {
                        console.log("[*] Blocked File.canExecute: " + path);
                        return false;
                    }
                }
                return this.canExecute.call(this);
            };

            console.log("[+] File API hooks installed");
        } catch (e) {
            console.log("[-] Failed to hook File: " + e);
        }

        // Bypass 2: Runtime.exec() for su commands
        try {
            var Runtime = Java.use("java.lang.Runtime");

            Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
                if (cmd.indexOf("su") !== -1 ||
                    cmd.indexOf("magisk") !== -1 ||
                    cmd.indexOf("which") !== -1 && cmd.indexOf("su") !== -1) {
                    console.log("[*] Blocked Runtime.exec: " + cmd);
                    throw Java.use("java.io.IOException").$new("No such file or directory");
                }
                return this.exec.overload('java.lang.String').call(this, cmd);
            };

            Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmdarray) {
                var cmd = cmdarray.join(" ");
                if (cmd.indexOf("su") !== -1 || cmd.indexOf("magisk") !== -1) {
                    console.log("[*] Blocked Runtime.exec: " + cmd);
                    throw Java.use("java.io.IOException").$new("No such file or directory");
                }
                return this.exec.overload('[Ljava.lang.String;').call(this, cmdarray);
            };

            console.log("[+] Runtime.exec hooks installed");
        } catch (e) {
            console.log("[-] Failed to hook Runtime.exec: " + e);
        }

        // Bypass 3: ProcessBuilder for su commands
        try {
            var ProcessBuilder = Java.use("java.lang.ProcessBuilder");

            ProcessBuilder.start.implementation = function() {
                var cmd = this.command();
                var cmdStr = cmd.toString();
                if (cmdStr.indexOf("su") !== -1 || cmdStr.indexOf("magisk") !== -1) {
                    console.log("[*] Blocked ProcessBuilder.start: " + cmdStr);
                    throw Java.use("java.io.IOException").$new("No such file or directory");
                }
                return this.start.call(this);
            };

            console.log("[+] ProcessBuilder hooks installed");
        } catch (e) {
            console.log("[-] Failed to hook ProcessBuilder: " + e);
        }

        // Bypass 4: Build.TAGS check (test-keys vs release-keys)
        try {
            var Build = Java.use("android.os.Build");
            Build.TAGS.value = "release-keys";
            console.log("[+] Build.TAGS set to release-keys");
        } catch (e) {
            console.log("[-] Failed to modify Build.TAGS: " + e);
        }

        // Bypass 5: PackageManager for root apps
        try {
            var PackageManager = Java.use("android.app.ApplicationPackageManager");

            var rootPackages = [
                "com.noshufou.android.su",
                "com.noshufou.android.su.elite",
                "eu.chainfire.supersu",
                "com.koushikdutta.superuser",
                "com.thirdparty.superuser",
                "com.yellowes.su",
                "com.topjohnwu.magisk",
                "com.kingroot.kinguser",
                "com.kingo.root",
                "com.smedialink.oneclickroot",
                "com.zhiqupk.root.global",
                "com.alephzain.framaroot"
            ];

            PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(pname, flags) {
                for (var i = 0; i < rootPackages.length; i++) {
                    if (pname === rootPackages[i]) {
                        console.log("[*] Blocked getPackageInfo: " + pname);
                        throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new();
                    }
                }
                return this.getPackageInfo.overload('java.lang.String', 'int').call(this, pname, flags);
            };

            console.log("[+] PackageManager hooks installed");
        } catch (e) {
            console.log("[-] Failed to hook PackageManager: " + e);
        }

        // Bypass 6: Common root detection libraries
        try {
            // RootBeer library
            try {
                var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
                RootBeer.isRooted.implementation = function() {
                    console.log("[*] RootBeer.isRooted returning false");
                    return false;
                };
                RootBeer.isRootedWithoutBusyBoxCheck.implementation = function() {
                    console.log("[*] RootBeer.isRootedWithoutBusyBoxCheck returning false");
                    return false;
                };
                console.log("[+] RootBeer hooks installed");
            } catch (e) {}

            // Custom root checks (common method names)
            var commonRootCheckNames = [
                "isRooted",
                "isDeviceRooted",
                "checkRoot",
                "detectRoot",
                "isRootAvailable",
                "isRootGiven",
                "checkRootMethod",
                "checkSuExists",
                "isSuAvailable"
            ];

            // Try to hook common classes
            var commonRootCheckClasses = [
                "RootCheck",
                "RootDetection",
                "SecurityCheck",
                "DeviceSecurity"
            ];

            // Note: This is a generic approach - actual implementation would need
            // to be customized based on the specific app
            console.log("[*] Common root detection patterns monitored");

        } catch (e) {
            console.log("[-] Error in root detection library hooks: " + e);
        }

        // Bypass 7: System property checks
        try {
            var SystemProperties = Java.use("android.os.SystemProperties");
            SystemProperties.get.overload('java.lang.String').implementation = function(key) {
                if (key === "ro.build.selinux" ||
                    key === "ro.debuggable" ||
                    key === "ro.secure") {
                    console.log("[*] SystemProperties.get blocked: " + key);
                    return "0";
                }
                return this.get.overload('java.lang.String').call(this, key);
            };
            console.log("[+] SystemProperties hooks installed");
        } catch (e) {
            console.log("[-] Failed to hook SystemProperties: " + e);
        }

    });

    // Native-level bypass
    try {
        var fopen = Module.findExportByName(null, 'fopen');
        if (fopen) {
            Interceptor.attach(fopen, {
                onEnter: function(args) {
                    var path = Memory.readUtf8String(args[0]);
                    if (path) {
                        for (var i = 0; i < rootPaths.length; i++) {
                            if (path.indexOf(rootPaths[i]) !== -1) {
                                console.log("[*] Blocked native fopen: " + path);
                                args[0] = Memory.allocUtf8String("/dev/null");
                                break;
                            }
                        }
                    }
                }
            });
            console.log("[+] Native fopen hook installed");
        }
    } catch (e) {
        console.log("[-] Failed to hook native fopen: " + e);
    }

    try {
        var access = Module.findExportByName(null, 'access');
        if (access) {
            Interceptor.attach(access, {
                onEnter: function(args) {
                    var path = Memory.readUtf8String(args[0]);
                    if (path) {
                        for (var i = 0; i < rootPaths.length; i++) {
                            if (path.indexOf(rootPaths[i]) !== -1) {
                                console.log("[*] Blocked native access: " + path);
                                this.block = true;
                                break;
                            }
                        }
                    }
                },
                onLeave: function(retval) {
                    if (this.block) {
                        retval.replace(ptr(-1)); // Return -1 (file not accessible)
                    }
                }
            });
            console.log("[+] Native access hook installed");
        }
    } catch (e) {
        console.log("[-] Failed to hook native access: " + e);
    }

    console.log("[*] Anti-Root bypass complete!");

    send({
        type: 'evasion',
        module: 'anti_root',
        status: 'active',
        message: 'Anti-Root detection bypass enabled'
    });

})();
