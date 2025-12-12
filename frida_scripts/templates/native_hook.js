/**
 * Native Function Hooking Template
 *
 * This template hooks native functions and logs arguments, return values, and register states.
 *
 * Template variables:
 *   - MODULE_NAME: Module name (e.g., "libnative.so" or null for any module)
 *   - FUNCTION_NAME: Function name or address (e.g., "strcmp" or "0x12345")
 *   - LOG_ARGS: Whether to log arguments (true/false)
 *   - LOG_RETURN: Whether to log return value (true/false)
 *   - LOG_REGISTERS: Whether to log register state (true/false)
 *   - LOG_BACKTRACE: Whether to log backtrace (true/false)
 *   - ARG_COUNT: Number of arguments to log (default: 4)
 */

(function() {
    var moduleName = MODULE_NAME;
    var functionName = "FUNCTION_NAME";
    var logArgs = LOG_ARGS;
    var logReturn = LOG_RETURN;
    var logRegisters = LOG_REGISTERS;
    var logBacktrace = LOG_BACKTRACE;
    var argCount = ARG_COUNT;

    try {
        var targetAddress = null;

        // Resolve function address
        if (functionName.startsWith('0x')) {
            // Direct address
            targetAddress = ptr(functionName);
        } else {
            // Symbol name
            if (moduleName) {
                var module = Process.getModuleByName(moduleName);
                targetAddress = module.getExportByName(functionName);
                if (!targetAddress) {
                    send({
                        type: 'error',
                        message: 'Function not found in module: ' + functionName + ' in ' + moduleName
                    });
                    return;
                }
            } else {
                // Search in all modules
                var exports = Module.enumerateExports(functionName);
                if (exports.length === 0) {
                    send({
                        type: 'error',
                        message: 'Function not found: ' + functionName
                    });
                    return;
                } else if (exports.length > 1) {
                    send({
                        type: 'warning',
                        message: 'Multiple exports found for ' + functionName + ', using first one'
                    });
                }
                targetAddress = exports[0].address;
                moduleName = exports[0].module;
            }
        }

        send({
            type: 'info',
            message: 'Hooking native function: ' + functionName + ' at ' + targetAddress + ' in ' + (moduleName || 'unknown')
        });

        // Create interceptor
        Interceptor.attach(targetAddress, {
            onEnter: function(args) {
                var threadId = Process.getCurrentThreadId();
                var timestamp = new Date().toISOString();

                var hookEvent = {
                    type: 'hook',
                    timestamp: timestamp,
                    threadId: threadId,
                    module: moduleName,
                    function: functionName,
                    address: targetAddress.toString(),
                    stage: 'enter'
                };

                // Log arguments
                if (logArgs) {
                    var argValues = [];
                    for (var i = 0; i < argCount; i++) {
                        try {
                            var argPtr = args[i];
                            var argInfo = {
                                index: i,
                                pointer: argPtr.toString()
                            };

                            // Try to read as integer
                            try {
                                argInfo.int = argPtr.toInt32();
                            } catch (e) {}

                            // Try to read as string
                            try {
                                var strVal = argPtr.readUtf8String(100);
                                if (strVal && strVal.length > 0) {
                                    argInfo.string = strVal;
                                }
                            } catch (e) {}

                            // Try to read as C string
                            try {
                                var cStrVal = argPtr.readCString(100);
                                if (cStrVal && cStrVal.length > 0) {
                                    argInfo.cstring = cStrVal;
                                }
                            } catch (e) {}

                            argValues.push(argInfo);
                        } catch (e) {
                            argValues.push({
                                index: i,
                                error: e.message
                            });
                        }
                    }
                    hookEvent.arguments = argValues;
                }

                // Log registers (ARM/ARM64)
                if (logRegisters) {
                    var regs = {};
                    try {
                        if (Process.arch === 'arm64') {
                            for (var i = 0; i < 8; i++) {
                                regs['x' + i] = this.context['x' + i].toString();
                            }
                            regs['lr'] = this.context.lr.toString();
                            regs['sp'] = this.context.sp.toString();
                            regs['pc'] = this.context.pc.toString();
                        } else if (Process.arch === 'arm') {
                            for (var i = 0; i < 4; i++) {
                                regs['r' + i] = this.context['r' + i].toString();
                            }
                            regs['lr'] = this.context.lr.toString();
                            regs['sp'] = this.context.sp.toString();
                            regs['pc'] = this.context.pc.toString();
                        } else if (Process.arch === 'ia32') {
                            regs['eax'] = this.context.eax.toString();
                            regs['ebx'] = this.context.ebx.toString();
                            regs['ecx'] = this.context.ecx.toString();
                            regs['edx'] = this.context.edx.toString();
                            regs['esp'] = this.context.esp.toString();
                            regs['eip'] = this.context.eip.toString();
                        } else if (Process.arch === 'x64') {
                            regs['rax'] = this.context.rax.toString();
                            regs['rbx'] = this.context.rbx.toString();
                            regs['rcx'] = this.context.rcx.toString();
                            regs['rdx'] = this.context.rdx.toString();
                            regs['rsp'] = this.context.rsp.toString();
                            regs['rip'] = this.context.rip.toString();
                        }
                        hookEvent.registers = regs;
                    } catch (e) {
                        hookEvent.registers = { error: e.message };
                    }
                }

                // Get backtrace
                if (logBacktrace) {
                    try {
                        var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .map(DebugSymbol.fromAddress)
                            .slice(0, 10)
                            .map(function(symbol) {
                                return symbol.toString();
                            });
                        hookEvent.backtrace = backtrace;
                    } catch (e) {
                        hookEvent.backtrace = ['<error: ' + e.message + '>'];
                    }
                }

                // Store for onLeave
                this.hookEvent = hookEvent;

                // Send enter event
                send(hookEvent);
            },

            onLeave: function(retval) {
                if (!logReturn) {
                    return;
                }

                var timestamp = new Date().toISOString();

                var hookEvent = {
                    type: 'hook',
                    timestamp: timestamp,
                    threadId: Process.getCurrentThreadId(),
                    module: moduleName,
                    function: functionName,
                    address: targetAddress.toString(),
                    stage: 'leave'
                };

                // Log return value
                try {
                    var retInfo = {
                        pointer: retval.toString()
                    };

                    // Try to read as integer
                    try {
                        retInfo.int = retval.toInt32();
                    } catch (e) {}

                    // Try to read as string
                    try {
                        var strVal = retval.readUtf8String(100);
                        if (strVal && strVal.length > 0) {
                            retInfo.string = strVal;
                        }
                    } catch (e) {}

                    hookEvent.returnValue = retInfo;
                } catch (e) {
                    hookEvent.returnValue = { error: e.message };
                }

                // Send leave event
                send(hookEvent);
            }
        });

        send({
            type: 'info',
            message: 'Successfully hooked: ' + functionName
        });

    } catch (e) {
        send({
            type: 'error',
            message: 'Failed to hook: ' + e.message,
            stack: e.stack
        });
    }
})();
