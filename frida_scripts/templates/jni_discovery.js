/**
 * JNI Discovery Script
 *
 * Discovers JNI functions and RegisterNatives calls in Android applications
 * Useful for finding native methods and JNI bridges
 */

Java.perform(function() {
    console.log("[*] JNI Discovery started");

    var jniMethods = [];
    var registerNativesCalls = [];

    // Hook RegisterNatives to intercept JNI method registrations
    try {
        var env = Java.vm.getEnv();
        var RegisterNatives = env.registerNatives;

        if (RegisterNatives) {
            Interceptor.attach(RegisterNatives.implementation, {
                onEnter: function(args) {
                    try {
                        // args[0] = JNIEnv*
                        // args[1] = jclass
                        // args[2] = JNINativeMethod* (array of methods)
                        // args[3] = jint (number of methods)

                        var className = null;
                        var methods = [];
                        var nMethods = args[3].toInt32();

                        // Get class name
                        try {
                            var jclass = Java.cast(args[1], Java.use("java.lang.Class"));
                            className = jclass.getName();
                        } catch (e) {
                            className = "<unknown>";
                        }

                        // Read JNINativeMethod array
                        if (nMethods > 0 && nMethods < 100) {
                            var methodsArray = args[2];

                            for (var i = 0; i < nMethods; i++) {
                                try {
                                    // JNINativeMethod structure:
                                    // - const char* name
                                    // - const char* signature
                                    // - void* fnPtr

                                    var offset = Process.pointerSize === 8 ? i * 24 : i * 12;
                                    var methodStruct = methodsArray.add(offset);

                                    var namePtr = methodStruct.readPointer();
                                    var sigPtr = methodStruct.add(Process.pointerSize).readPointer();
                                    var fnPtr = methodStruct.add(Process.pointerSize * 2).readPointer();

                                    var methodName = namePtr.readCString();
                                    var methodSig = sigPtr.readCString();

                                    methods.push({
                                        name: methodName,
                                        signature: methodSig,
                                        address: fnPtr.toString()
                                    });
                                } catch (e) {
                                    console.log("[-] Error reading method " + i + ": " + e);
                                }
                            }
                        }

                        var registrationInfo = {
                            type: 'jni_register',
                            className: className,
                            methodCount: nMethods,
                            methods: methods,
                            timestamp: new Date().toISOString()
                        };

                        registerNativesCalls.push(registrationInfo);
                        send(registrationInfo);

                        console.log("[+] RegisterNatives: " + className + " (" + nMethods + " methods)");
                        methods.forEach(function(m) {
                            console.log("    - " + m.name + m.signature + " @ " + m.address);
                        });

                    } catch (e) {
                        console.log("[-] Error in RegisterNatives hook: " + e);
                    }
                }
            });

            console.log("[+] RegisterNatives hook installed");
        }
    } catch (e) {
        console.log("[-] Failed to hook RegisterNatives: " + e);
    }

    // Enumerate all loaded classes and find native methods
    function enumerateNativeMethods() {
        console.log("[*] Enumerating native methods...");

        Java.enumerateLoadedClasses({
            onMatch: function(className) {
                try {
                    var clazz = Java.use(className);

                    // Get all declared methods
                    var methods = clazz.class.getDeclaredMethods();

                    methods.forEach(function(method) {
                        try {
                            var modifiers = method.getModifiers();
                            // Check if method is native (0x100 = NATIVE modifier)
                            if ((modifiers & 0x100) !== 0) {
                                var methodInfo = {
                                    type: 'native_method',
                                    className: className,
                                    methodName: method.getName(),
                                    signature: method.toString(),
                                    modifiers: modifiers.toString(16)
                                };

                                jniMethods.push(methodInfo);

                                console.log("[+] Native method: " + className + "." + method.getName());
                            }
                        } catch (e) {
                            // Skip methods that throw exceptions
                        }
                    });

                } catch (e) {
                    // Skip classes that cannot be loaded
                }
            },
            onComplete: function() {
                console.log("[*] Native method enumeration complete");
                console.log("[*] Found " + jniMethods.length + " native methods");

                send({
                    type: 'jni_summary',
                    nativeMethods: jniMethods,
                    registerNativesCalls: registerNativesCalls,
                    totalNativeMethods: jniMethods.length,
                    totalRegistrations: registerNativesCalls.length
                });
            }
        });
    }

    // Start enumeration after a short delay
    setTimeout(enumerateNativeMethods, 2000);

    console.log("[*] JNI Discovery initialized");
});
