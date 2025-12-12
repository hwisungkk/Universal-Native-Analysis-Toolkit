/**
 * Java Method Hooking Template
 *
 * This template hooks Java methods and logs parameters, return values, and backtraces.
 *
 * Template variables:
 *   - CLASS_NAME: Fully qualified class name (e.g., "com.example.MyClass")
 *   - METHOD_NAME: Method name to hook (e.g., "myMethod")
 *   - OVERLOAD_INDEX: Optional overload index (-1 for all overloads)
 *   - LOG_ARGS: Whether to log arguments (true/false)
 *   - LOG_RETURN: Whether to log return value (true/false)
 *   - LOG_BACKTRACE: Whether to log backtrace (true/false)
 */

Java.perform(function() {
    var targetClass = "CLASS_NAME";
    var targetMethod = "METHOD_NAME";
    var overloadIndex = OVERLOAD_INDEX;
    var logArgs = LOG_ARGS;
    var logReturn = LOG_RETURN;
    var logBacktrace = LOG_BACKTRACE;

    try {
        var clazz = Java.use(targetClass);

        // Get all overloads
        var overloads = clazz[targetMethod].overloads;

        if (overloads.length === 0) {
            send({
                type: 'error',
                message: 'Method not found: ' + targetMethod
            });
            return;
        }

        send({
            type: 'info',
            message: 'Found ' + overloads.length + ' overload(s) for ' + targetClass + '.' + targetMethod
        });

        // Hook specific overload or all
        var overloadsToHook = [];
        if (overloadIndex >= 0 && overloadIndex < overloads.length) {
            overloadsToHook.push(overloadIndex);
        } else {
            for (var i = 0; i < overloads.length; i++) {
                overloadsToHook.push(i);
            }
        }

        overloadsToHook.forEach(function(idx) {
            var methodSignature = overloads[idx].toString();

            clazz[targetMethod].overloads[idx].implementation = function() {
                var args = Array.prototype.slice.call(arguments);
                var threadId = Process.getCurrentThreadId();
                var timestamp = new Date().toISOString();

                // Prepare hook event
                var hookEvent = {
                    type: 'hook',
                    timestamp: timestamp,
                    threadId: threadId,
                    className: targetClass,
                    methodName: targetMethod,
                    signature: methodSignature,
                    overloadIndex: idx
                };

                // Log arguments
                if (logArgs) {
                    var argStrings = [];
                    for (var i = 0; i < args.length; i++) {
                        try {
                            if (args[i] === null) {
                                argStrings.push('null');
                            } else if (args[i] === undefined) {
                                argStrings.push('undefined');
                            } else {
                                var argStr = args[i].toString();
                                // Truncate long strings
                                if (argStr.length > 200) {
                                    argStr = argStr.substring(0, 200) + '...';
                                }
                                argStrings.push(argStr);
                            }
                        } catch (e) {
                            argStrings.push('<error: ' + e.message + '>');
                        }
                    }
                    hookEvent.arguments = argStrings;
                }

                // Get backtrace
                if (logBacktrace) {
                    try {
                        var backtrace = Java.use("android.util.Log")
                            .getStackTraceString(Java.use("java.lang.Exception").$new());
                        hookEvent.backtrace = backtrace.split('\n').slice(0, 10); // First 10 lines
                    } catch (e) {
                        hookEvent.backtrace = ['<error: ' + e.message + '>'];
                    }
                }

                // Call original method
                var retval;
                var exception = null;
                try {
                    retval = this[targetMethod].apply(this, args);
                } catch (e) {
                    exception = e;
                }

                // Log return value
                if (logReturn && !exception) {
                    try {
                        if (retval === null) {
                            hookEvent.returnValue = 'null';
                        } else if (retval === undefined) {
                            hookEvent.returnValue = 'void';
                        } else {
                            var retStr = retval.toString();
                            if (retStr.length > 200) {
                                retStr = retStr.substring(0, 200) + '...';
                            }
                            hookEvent.returnValue = retStr;
                        }
                    } catch (e) {
                        hookEvent.returnValue = '<error: ' + e.message + '>';
                    }
                }

                // Log exception
                if (exception) {
                    hookEvent.exception = exception.toString();
                }

                // Send hook event to Python
                send(hookEvent);

                // Re-throw exception if any
                if (exception) {
                    throw exception;
                }

                return retval;
            };

            send({
                type: 'info',
                message: 'Hooked: ' + targetClass + '.' + targetMethod + ' [' + idx + ']'
            });
        });

    } catch (e) {
        send({
            type: 'error',
            message: 'Failed to hook: ' + e.message,
            stack: e.stack
        });
    }
});
