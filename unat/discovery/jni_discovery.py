#!/usr/bin/env python3
"""
JNI Discovery Module
Discovers JNI functions and RegisterNatives calls in Android applications
"""

import logging
import time
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from pathlib import Path

try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False
    logging.warning("Frida not available. JNI discovery features will be limited.")


@dataclass
class JNINativeMethod:
    """Data class to store JNI native method information"""
    class_name: str
    method_name: str
    signature: str
    address: Optional[str] = None
    is_registered: bool = False  # True if found via RegisterNatives


@dataclass
class JNIRegistration:
    """Data class to store RegisterNatives call information"""
    class_name: str
    method_count: int
    methods: List[Dict[str, str]] = field(default_factory=list)
    timestamp: str = ""


@dataclass
class JNIDiscoveryResult:
    """Data class to store JNI discovery results"""
    package_name: str
    total_native_methods: int = 0
    total_registrations: int = 0
    native_methods: List[JNINativeMethod] = field(default_factory=list)
    registrations: List[JNIRegistration] = field(default_factory=list)


class JNIDiscovery:
    """
    JNI Discovery for finding JNI functions and RegisterNatives calls
    Uses Frida to dynamically inspect JNI bridge
    """

    def __init__(self, frida_device, package_name: str):
        """
        Initialize JNI Discovery

        Args:
            frida_device: Frida device object
            package_name: Target package name

        Raises:
            ImportError: If Frida is not available
        """
        if not FRIDA_AVAILABLE:
            raise ImportError("Frida is required but not installed")

        self.logger = logging.getLogger(__name__)
        self.device = frida_device
        self.package_name = package_name
        self.session: Optional[frida.core.Session] = None
        self.script: Optional[frida.core.Script] = None

        # Storage for discovered data
        self.native_methods: List[JNINativeMethod] = []
        self.registrations: List[JNIRegistration] = []

    def attach(self, spawn: bool = False) -> bool:
        """
        Attach to the target process

        Args:
            spawn: If True, spawn the app; if False, attach to running process

        Returns:
            bool: True if attached successfully
        """
        try:
            if spawn:
                self.logger.info(f"Spawning {self.package_name}...")
                pid = self.device.spawn([self.package_name])
                self.session = self.device.attach(pid)
                self.device.resume(pid)
            else:
                self.logger.info(f"Attaching to {self.package_name}...")
                self.session = self.device.attach(self.package_name)

            self.logger.info("Attached successfully")
            return True

        except frida.ProcessNotFoundError:
            self.logger.error(f"Process not found: {self.package_name}")
            return False
        except Exception as e:
            self.logger.error(f"Failed to attach: {e}")
            return False

    def detach(self):
        """Detach from the target process"""
        if self.script:
            self.script.unload()
            self.script = None

        if self.session:
            self.session.detach()
            self.session = None

        self.logger.info("Detached")

    def discover(self, timeout: int = 5) -> JNIDiscoveryResult:
        """
        Perform JNI discovery

        Args:
            timeout: How long to wait for discovery (seconds)

        Returns:
            JNIDiscoveryResult: Discovery results
        """
        if not self.session:
            raise RuntimeError("Not attached to any process. Call attach() first.")

        # Load JNI discovery script
        script_path = Path(__file__).parent.parent.parent / "frida_scripts" / "templates" / "jni_discovery.js"

        if script_path.exists():
            with open(script_path, 'r', encoding='utf-8') as f:
                script_code = f.read()
        else:
            # Fallback: inline script (simplified version)
            script_code = self._get_jni_discovery_script()

        self.logger.info("Starting JNI discovery...")

        # Execute script
        script = self.session.create_script(script_code)

        def on_message(message, data):
            if message['type'] == 'send':
                payload = message['payload']
                msg_type = payload.get('type')

                if msg_type == 'jni_register':
                    # RegisterNatives call detected
                    registration = JNIRegistration(
                        class_name=payload.get('className', '<unknown>'),
                        method_count=payload.get('methodCount', 0),
                        methods=payload.get('methods', []),
                        timestamp=payload.get('timestamp', '')
                    )
                    self.registrations.append(registration)

                    # Also add to native methods list
                    for method in payload.get('methods', []):
                        native_method = JNINativeMethod(
                            class_name=payload.get('className', '<unknown>'),
                            method_name=method.get('name', ''),
                            signature=method.get('signature', ''),
                            address=method.get('address', ''),
                            is_registered=True
                        )
                        self.native_methods.append(native_method)

                elif msg_type == 'native_method':
                    # Native method found via enumeration
                    native_method = JNINativeMethod(
                        class_name=payload.get('className', ''),
                        method_name=payload.get('methodName', ''),
                        signature=payload.get('signature', ''),
                        is_registered=False
                    )
                    self.native_methods.append(native_method)

                elif msg_type == 'jni_summary':
                    # Final summary
                    self.logger.info(
                        f"JNI Discovery complete: {payload.get('totalNativeMethods', 0)} "
                        f"native methods, {payload.get('totalRegistrations', 0)} registrations"
                    )

            elif message['type'] == 'error':
                self.logger.error(f"Script error: {message.get('description', 'Unknown error')}")

        script.on('message', on_message)
        script.load()

        # Wait for discovery to complete
        self.logger.info(f"Waiting {timeout} seconds for JNI discovery...")
        time.sleep(timeout)

        script.unload()

        # Build result
        result = JNIDiscoveryResult(
            package_name=self.package_name,
            total_native_methods=len(self.native_methods),
            total_registrations=len(self.registrations),
            native_methods=self.native_methods,
            registrations=self.registrations
        )

        return result

    @staticmethod
    def _get_jni_discovery_script() -> str:
        """Fallback inline script for JNI discovery"""
        return """
        Java.perform(function() {
            console.log("[*] JNI Discovery (fallback) started");

            // Enumerate native methods
            Java.enumerateLoadedClasses({
                onMatch: function(className) {
                    try {
                        var clazz = Java.use(className);
                        var methods = clazz.class.getDeclaredMethods();

                        methods.forEach(function(method) {
                            try {
                                var modifiers = method.getModifiers();
                                if ((modifiers & 0x100) !== 0) {
                                    send({
                                        type: 'native_method',
                                        className: className,
                                        methodName: method.getName(),
                                        signature: method.toString()
                                    });
                                }
                            } catch (e) {}
                        });
                    } catch (e) {}
                },
                onComplete: function() {
                    console.log("[*] Native method enumeration complete");
                }
            });
        });
        """


def discover_jni_functions(
    frida_device,
    package_name: str,
    spawn: bool = False,
    timeout: int = 5
) -> Optional[JNIDiscoveryResult]:
    """
    Convenience function to discover JNI functions

    Args:
        frida_device: Frida device object
        package_name: Target package name
        spawn: Spawn the app instead of attaching
        timeout: Discovery timeout in seconds

    Returns:
        Optional[JNIDiscoveryResult]: Discovery results or None if failed
    """
    discovery = JNIDiscovery(frida_device, package_name)

    try:
        if not discovery.attach(spawn=spawn):
            return None

        result = discovery.discover(timeout=timeout)
        return result

    except Exception as e:
        logging.error(f"JNI discovery failed: {e}")
        return None

    finally:
        discovery.detach()
