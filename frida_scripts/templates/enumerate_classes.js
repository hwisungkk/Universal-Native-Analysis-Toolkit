/**
 * Enumerate Loaded Java Classes
 *
 * This script enumerates all loaded Java classes in the target application.
 * It can be used to discover available classes for further analysis.
 *
 * Usage:
 *   - Load this script into a Frida session
 *   - The script will send back an array of class names
 */

Java.perform(function() {
    console.log("[*] Enumerating loaded Java classes...");

    var classes = [];
    var startTime = Date.now();

    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            classes.push(className);
        },
        onComplete: function() {
            var endTime = Date.now();
            var duration = (endTime - startTime) / 1000;

            console.log("[+] Enumeration complete!");
            console.log("[+] Found " + classes.length + " classes in " + duration + "s");

            // Send results back to Python
            send(classes);
        }
    });
});
