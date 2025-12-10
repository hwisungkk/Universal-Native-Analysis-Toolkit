/**
 * Enumerate Methods of a Java Class
 *
 * This script enumerates all methods (including constructors) of a specific Java class.
 * Replace CLASS_NAME_PLACEHOLDER with the target class name before loading.
 *
 * Usage:
 *   - Replace CLASS_NAME_PLACEHOLDER with actual class name
 *   - Load this script into a Frida session
 *   - The script will send back an array of method signatures
 */

Java.perform(function() {
    var className = "CLASS_NAME_PLACEHOLDER";
    console.log("[*] Enumerating methods for: " + className);

    var methods = [];

    try {
        // Load the target class
        var targetClass = Java.use(className);

        // Get all declared methods (public, private, protected)
        var methodObjects = targetClass.class.getDeclaredMethods();

        console.log("[+] Found " + methodObjects.length + " methods");

        // Extract method information
        methodObjects.forEach(function(method) {
            var methodStr = method.toString();

            // Parse method details
            var returnType = method.getReturnType().getName();
            var methodName = method.getName();
            var params = [];

            var paramTypes = method.getParameterTypes();
            for (var i = 0; i < paramTypes.length; i++) {
                params.push(paramTypes[i].getName());
            }

            var signature = {
                name: methodName,
                returnType: returnType,
                parameters: params,
                fullSignature: methodStr,
                modifiers: method.getModifiers()
            };

            methods.push(signature.fullSignature);
        });

        // Also get constructors
        var constructors = targetClass.class.getDeclaredConstructors();
        console.log("[+] Found " + constructors.length + " constructors");

        constructors.forEach(function(constructor) {
            methods.push(constructor.toString());
        });

        console.log("[+] Total: " + methods.length + " methods/constructors");

        // Send results
        send(methods);

    } catch (e) {
        console.log("[-] Error: " + e.message);
        send([]);
    }
});
