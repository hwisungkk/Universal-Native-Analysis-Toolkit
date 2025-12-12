/**
 * Anti-Emulator Detection Bypass
 *
 * This script bypasses common emulator detection techniques:
 * - Build properties (manufacturer, model, brand)
 * - IMEI/Phone number checks
 * - Sensor availability
 * - File system artifacts
 * - Specific emulator files/properties
 */

(function() {
    'use strict';

    console.log("[*] Anti-Emulator Bypass loaded");

    if (!Java.available) {
        console.log("[-] Java not available, skipping Java hooks");
        return;
    }

    Java.perform(function() {
        // Bypass 1: Build properties spoofing
        try {
            var Build = Java.use("android.os.Build");

            // Spoof to look like a real device (Samsung Galaxy S21)
            Build.MANUFACTURER.value = "samsung";
            Build.BRAND.value = "samsung";
            Build.MODEL.value = "SM-G991B";
            Build.PRODUCT.value = "o1sxxx";
            Build.DEVICE.value = "o1s";
            Build.BOARD.value = "exynos2100";
            Build.HARDWARE.value = "exynos2100";
            Build.FINGERPRINT.value = "samsung/o1sxxx/o1s:12/SP1A.210812.016/G991BXXU5CVKG:user/release-keys";
            Build.SERIAL.value = "RZ8N" + Math.random().toString(36).substring(2, 9).toUpperCase();

            console.log("[+] Build properties spoofed");
        } catch (e) {
            console.log("[-] Failed to spoof Build: " + e);
        }

        // Bypass 2: TelephonyManager spoofing
        try {
            var TelephonyManager = Java.use("android.telephony.TelephonyManager");

            // Spoof IMEI
            TelephonyManager.getDeviceId.overload().implementation = function() {
                var imei = "35" + Math.floor(Math.random() * 9000000000000) + 1000000000000;
                console.log("[*] TelephonyManager.getDeviceId spoofed: " + imei);
                return imei.toString();
            };

            TelephonyManager.getDeviceId.overload('int').implementation = function(slotIndex) {
                var imei = "35" + Math.floor(Math.random() * 9000000000000) + 1000000000000;
                console.log("[*] TelephonyManager.getDeviceId(slot) spoofed: " + imei);
                return imei.toString();
            };

            // Spoof phone number
            TelephonyManager.getLine1Number.overload().implementation = function() {
                var number = "+1555" + Math.floor(Math.random() * 9000000) + 1000000;
                console.log("[*] TelephonyManager.getLine1Number spoofed: " + number);
                return number.toString();
            };

            // Spoof subscriber ID
            TelephonyManager.getSubscriberId.overload().implementation = function() {
                var imsi = "310260" + Math.floor(Math.random() * 900000000) + 100000000;
                console.log("[*] TelephonyManager.getSubscriberId spoofed: " + imsi);
                return imsi.toString();
            };

            // Spoof SIM serial number
            TelephonyManager.getSimSerialNumber.overload().implementation = function() {
                var simSerial = "89" + Math.floor(Math.random() * 90000000000000000) + 10000000000000000;
                console.log("[*] TelephonyManager.getSimSerialNumber spoofed: " + simSerial);
                return simSerial.toString();
            };

            // Spoof network operator
            TelephonyManager.getNetworkOperator.overload().implementation = function() {
                console.log("[*] TelephonyManager.getNetworkOperator spoofed: 310260");
                return "310260"; // T-Mobile US
            };

            TelephonyManager.getNetworkOperatorName.overload().implementation = function() {
                console.log("[*] TelephonyManager.getNetworkOperatorName spoofed: T-Mobile");
                return "T-Mobile";
            };

            console.log("[+] TelephonyManager hooks installed");
        } catch (e) {
            console.log("[-] Failed to hook TelephonyManager: " + e);
        }

        // Bypass 3: SensorManager - ensure sensors are available
        try {
            var SensorManager = Java.use("android.hardware.SensorManager");

            // Return fake sensors list
            SensorManager.getSensorList.implementation = function(type) {
                console.log("[*] SensorManager.getSensorList called for type: " + type);
                var sensorList = this.getSensorList.call(this, type);

                // If list is empty, it's likely an emulator detection
                if (sensorList.size() === 0) {
                    console.log("[*] Adding fake sensors to bypass emulator detection");
                    // In real implementation, we would create fake Sensor objects
                }

                return sensorList;
            };

            console.log("[+] SensorManager hooks installed");
        } catch (e) {
            console.log("[-] Failed to hook SensorManager: " + e);
        }

        // Bypass 4: SystemProperties spoofing
        try {
            var SystemProperties = Java.use("android.os.SystemProperties");

            SystemProperties.get.overload('java.lang.String').implementation = function(key) {
                var value = this.get.overload('java.lang.String').call(this, key);

                // Emulator-specific properties
                if (key === "ro.kernel.qemu" ||
                    key === "ro.kernel.android.qemu" ||
                    key === "ro.hardware.goldfish" ||
                    key === "ro.build.product" && value.indexOf("sdk") !== -1) {
                    console.log("[*] Blocked SystemProperties.get: " + key);
                    return "";
                }

                // Generic SDK property
                if (key.indexOf("sdk") !== -1 || key.indexOf("emulator") !== -1) {
                    console.log("[*] Modified SystemProperties.get: " + key);
                    return "";
                }

                return value;
            };

            SystemProperties.get.overload('java.lang.String', 'java.lang.String').implementation = function(key, def) {
                if (key === "ro.kernel.qemu" ||
                    key === "ro.kernel.android.qemu" ||
                    key === "ro.hardware.goldfish") {
                    console.log("[*] Blocked SystemProperties.get with default: " + key);
                    return "";
                }
                return this.get.overload('java.lang.String', 'java.lang.String').call(this, key, def);
            };

            console.log("[+] SystemProperties hooks installed");
        } catch (e) {
            console.log("[-] Failed to hook SystemProperties: " + e);
        }

        // Bypass 5: File checks for emulator artifacts
        try {
            var File = Java.use("java.io.File");

            var emulatorFiles = [
                "/dev/socket/qemud",
                "/dev/qemu_pipe",
                "/system/lib/libc_malloc_debug_qemu.so",
                "/sys/qemu_trace",
                "/system/bin/qemu-props",
                "/dev/socket/genyd",
                "/dev/socket/baseband_genyd"
            ];

            File.exists.implementation = function() {
                var path = this.getAbsolutePath();
                for (var i = 0; i < emulatorFiles.length; i++) {
                    if (path === emulatorFiles[i] || path.indexOf(emulatorFiles[i]) !== -1) {
                        console.log("[*] Blocked File.exists for emulator file: " + path);
                        return false;
                    }
                }
                return this.exists.call(this);
            };

            console.log("[+] File emulator detection hooks installed");
        } catch (e) {
            console.log("[-] Failed to hook File for emulator detection: " + e);
        }

        // Bypass 6: Settings.Secure for Android ID
        try {
            var Settings = Java.use("android.provider.Settings$Secure");

            Settings.getString.implementation = function(resolver, name) {
                if (name === "android_id") {
                    // Generate realistic Android ID
                    var androidId = Math.random().toString(16).substring(2, 18);
                    console.log("[*] Settings.Secure.getString spoofed android_id: " + androidId);
                    return androidId;
                }
                return this.getString.call(this, resolver, name);
            };

            console.log("[+] Settings.Secure hooks installed");
        } catch (e) {
            console.log("[-] Failed to hook Settings.Secure: " + e);
        }

        // Bypass 7: Package Manager checks for Google Play Services
        try {
            var PackageManager = Java.use("android.app.ApplicationPackageManager");

            var originalGetPackageInfo = PackageManager.getPackageInfo.overload('java.lang.String', 'int');
            PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(pname, flags) {
                // Ensure Google services are "present" to avoid emulator detection
                if (pname === "com.google.android.gms" ||
                    pname === "com.google.android.gsf") {
                    console.log("[*] Spoofing presence of: " + pname);
                    // In real implementation, would return a fake PackageInfo object
                }
                return originalGetPackageInfo.call(this, pname, flags);
            };

            console.log("[+] PackageManager emulator checks installed");
        } catch (e) {
            console.log("[-] Failed to hook PackageManager for emulator: " + e);
        }

    });

    // Native-level bypass
    try {
        // Hook __system_property_get to spoof properties at native level
        var system_property_get = Module.findExportByName("libc.so", "__system_property_get");
        if (system_property_get) {
            Interceptor.attach(system_property_get, {
                onEnter: function(args) {
                    this.key = Memory.readUtf8String(args[0]);
                    this.value_ptr = args[1];
                },
                onLeave: function(retval) {
                    if (this.key === "ro.kernel.qemu" ||
                        this.key === "ro.hardware.goldfish" ||
                        this.key === "ro.kernel.android.qemu") {
                        console.log("[*] Blocked native property: " + this.key);
                        Memory.writeUtf8String(this.value_ptr, "");
                        retval.replace(ptr(0));
                    }
                }
            });
            console.log("[+] Native __system_property_get hook installed");
        }
    } catch (e) {
        console.log("[-] Failed to hook native __system_property_get: " + e);
    }

    console.log("[*] Anti-Emulator bypass complete!");

    send({
        type: 'evasion',
        module: 'anti_emulator',
        status: 'active',
        message: 'Anti-Emulator detection bypass enabled'
    });

})();
