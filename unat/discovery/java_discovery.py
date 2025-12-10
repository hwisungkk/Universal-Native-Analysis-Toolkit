#!/usr/bin/env python3
"""
Java Discovery Module
Discovers Java classes and methods in Android applications using Frida
"""

import logging
import re
from typing import List, Dict, Optional, Set
from dataclasses import dataclass, field
from pathlib import Path

try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False
    logging.warning("Frida not available. Java discovery features will be limited.")


@dataclass
class JavaClassInfo:
    """Data class to store Java class information"""
    name: str
    methods: List[str] = field(default_factory=list)
    fields: List[str] = field(default_factory=list)
    is_obfuscated: bool = False
    package: str = ""


@dataclass
class JavaDiscoveryResult:
    """Data class to store discovery results"""
    package_name: str
    total_classes: int = 0
    total_methods: int = 0
    obfuscated_classes: int = 0
    classes: List[JavaClassInfo] = field(default_factory=list)


class JavaDiscovery:
    """
    Java Discovery for enumerating Java classes and methods
    Uses Frida to dynamically inspect loaded classes
    """

    def __init__(self, frida_device, package_name: str):
        """
        Initialize Java Discovery

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

        # Obfuscation patterns
        self.obfuscation_patterns = [
            r'^[a-z]$',  # Single letter: a, b, c
            r'^[a-z]\.[a-z]$',  # Two single letters: a.b
            r'^[a-z0-9]{1,3}$',  # Short names: ab, o0, l1l
            r'[O0][O0]',  # O0O, 00O patterns
            r'[lI1]{2,}',  # l1l, III patterns
        ]

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

    def _is_obfuscated(self, class_name: str) -> bool:
        """
        Check if a class name appears to be obfuscated

        Args:
            class_name: Fully qualified class name

        Returns:
            bool: True if likely obfuscated
        """
        # Get the simple class name (last part)
        parts = class_name.split('.')
        simple_name = parts[-1] if parts else class_name

        # Check against patterns
        for pattern in self.obfuscation_patterns:
            if re.search(pattern, simple_name):
                return True

        # Additional heuristics
        # Very short package names
        if len(parts) > 1 and all(len(p) <= 2 for p in parts[:-1]):
            return True

        return False

    def enumerate_classes(
        self,
        package_filter: Optional[str] = None,
        include_system: bool = False,
        obfuscated_only: bool = False
    ) -> List[JavaClassInfo]:
        """
        Enumerate loaded Java classes

        Args:
            package_filter: Only include classes from this package (default: target package)
            include_system: Include system classes (android.*, java.*, etc.)
            obfuscated_only: Only return obfuscated classes

        Returns:
            List[JavaClassInfo]: List of discovered classes
        """
        if not self.session:
            raise RuntimeError("Not attached to any process. Call attach() first.")

        # Use target package as default filter
        if package_filter is None and not include_system:
            package_filter = self.package_name

        # Load enumeration script
        script_path = Path(__file__).parent.parent.parent / "frida_scripts" / "templates" / "enumerate_classes.js"

        if script_path.exists():
            with open(script_path, 'r', encoding='utf-8') as f:
                script_code = f.read()
        else:
            # Fallback: inline script
            script_code = self._get_enumerate_classes_script()

        self.logger.info("Enumerating Java classes...")

        # Execute script
        script = self.session.create_script(script_code)
        classes_data = []

        def on_message(message, data):
            if message['type'] == 'send':
                classes_data.append(message['payload'])
            elif message['type'] == 'error':
                self.logger.error(f"Script error: {message['stack']}")

        script.on('message', on_message)
        script.load()

        # Wait for enumeration to complete
        import time
        time.sleep(2)

        script.unload()

        # Parse results
        classes = []
        for class_name in classes_data[0] if classes_data else []:
            # Apply filters
            if package_filter and not class_name.startswith(package_filter):
                continue

            if not include_system:
                if class_name.startswith(('java.', 'android.', 'dalvik.', 'com.android.')):
                    continue

            # Check obfuscation
            is_obf = self._is_obfuscated(class_name)

            if obfuscated_only and not is_obf:
                continue

            # Extract package
            parts = class_name.split('.')
            package = '.'.join(parts[:-1]) if len(parts) > 1 else ""

            class_info = JavaClassInfo(
                name=class_name,
                is_obfuscated=is_obf,
                package=package
            )
            classes.append(class_info)

        self.logger.info(f"Found {len(classes)} classes")
        return classes

    def enumerate_methods(self, class_name: str) -> List[str]:
        """
        Enumerate methods of a specific class

        Args:
            class_name: Fully qualified class name

        Returns:
            List[str]: List of method signatures
        """
        if not self.session:
            raise RuntimeError("Not attached to any process. Call attach() first.")

        # Load enumeration script
        script_path = Path(__file__).parent.parent.parent / "frida_scripts" / "templates" / "enumerate_methods.js"

        if script_path.exists():
            with open(script_path, 'r', encoding='utf-8') as f:
                script_code = f.read()
        else:
            # Fallback: inline script
            script_code = self._get_enumerate_methods_script()

        # Replace placeholder
        script_code = script_code.replace("CLASS_NAME_PLACEHOLDER", class_name)

        self.logger.debug(f"Enumerating methods for {class_name}...")

        # Execute script
        script = self.session.create_script(script_code)
        methods_data = []

        def on_message(message, data):
            if message['type'] == 'send':
                methods_data.append(message['payload'])
            elif message['type'] == 'error':
                self.logger.error(f"Script error: {message['stack']}")

        script.on('message', on_message)
        script.load()

        # Wait for enumeration
        import time
        time.sleep(0.5)

        script.unload()

        methods = methods_data[0] if methods_data else []
        self.logger.debug(f"Found {len(methods)} methods in {class_name}")

        return methods

    def discover(
        self,
        package_filter: Optional[str] = None,
        include_system: bool = False,
        obfuscated_only: bool = False,
        enumerate_methods: bool = True,
        max_classes: Optional[int] = None
    ) -> JavaDiscoveryResult:
        """
        Perform full Java discovery

        Args:
            package_filter: Filter classes by package
            include_system: Include system classes
            obfuscated_only: Only include obfuscated classes
            enumerate_methods: Also enumerate methods for each class
            max_classes: Maximum number of classes to process

        Returns:
            JavaDiscoveryResult: Discovery results
        """
        # Enumerate classes
        classes = self.enumerate_classes(
            package_filter=package_filter,
            include_system=include_system,
            obfuscated_only=obfuscated_only
        )

        # Limit classes if requested
        if max_classes:
            classes = classes[:max_classes]

        # Enumerate methods if requested
        total_methods = 0
        if enumerate_methods:
            for i, class_info in enumerate(classes):
                try:
                    methods = self.enumerate_methods(class_info.name)
                    class_info.methods = methods
                    total_methods += len(methods)

                    if (i + 1) % 10 == 0:
                        self.logger.info(f"Processed {i + 1}/{len(classes)} classes...")

                except Exception as e:
                    self.logger.warning(f"Failed to enumerate methods for {class_info.name}: {e}")

        # Build result
        result = JavaDiscoveryResult(
            package_name=self.package_name,
            total_classes=len(classes),
            total_methods=total_methods,
            obfuscated_classes=sum(1 for c in classes if c.is_obfuscated),
            classes=classes
        )

        return result

    @staticmethod
    def _get_enumerate_classes_script() -> str:
        """Fallback inline script for enumerating classes"""
        return """
        Java.perform(function() {
            var classes = [];
            Java.enumerateLoadedClasses({
                onMatch: function(className) {
                    classes.push(className);
                },
                onComplete: function() {
                    send(classes);
                }
            });
        });
        """

    @staticmethod
    def _get_enumerate_methods_script() -> str:
        """Fallback inline script for enumerating methods"""
        return """
        Java.perform(function() {
            var methods = [];
            try {
                var targetClass = Java.use("CLASS_NAME_PLACEHOLDER");
                var methodNames = targetClass.class.getDeclaredMethods();

                methodNames.forEach(function(method) {
                    methods.push(method.toString());
                });

                send(methods);
            } catch (e) {
                send([]);
            }
        });
        """


def discover_java_classes(
    frida_device,
    package_name: str,
    spawn: bool = False,
    package_only: bool = True,
    obfuscated_only: bool = False,
    enumerate_methods: bool = True
) -> Optional[JavaDiscoveryResult]:
    """
    Convenience function to discover Java classes

    Args:
        frida_device: Frida device object
        package_name: Target package name
        spawn: Spawn the app instead of attaching
        package_only: Only enumerate app's package classes
        obfuscated_only: Only include obfuscated classes
        enumerate_methods: Also enumerate methods

    Returns:
        Optional[JavaDiscoveryResult]: Discovery results or None if failed
    """
    discovery = JavaDiscovery(frida_device, package_name)

    try:
        if not discovery.attach(spawn=spawn):
            return None

        package_filter = package_name if package_only else None

        result = discovery.discover(
            package_filter=package_filter,
            include_system=not package_only,
            obfuscated_only=obfuscated_only,
            enumerate_methods=enumerate_methods
        )

        return result

    except Exception as e:
        logging.error(f"Discovery failed: {e}")
        return None

    finally:
        discovery.detach()
