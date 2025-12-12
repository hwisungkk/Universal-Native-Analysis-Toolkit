#!/usr/bin/env python3
"""
Frida Engine Module
Manages Frida sessions, script execution, and message handling
"""

import logging
import time
import signal
import sys
from typing import Optional, Callable, Dict, Any, List
from dataclasses import dataclass, field
from datetime import datetime

try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False
    logging.warning("Frida not available. Hooking features will be disabled.")


@dataclass
class HookEvent:
    """Represents a hook event"""
    timestamp: str
    thread_id: int
    event_type: str  # 'hook', 'info', 'error', 'warning'
    data: Dict[str, Any] = field(default_factory=dict)


class FridaEngine:
    """
    Frida Engine for managing hooking sessions
    Handles script loading, execution, and message processing
    """

    def __init__(self, frida_device, package_name: str):
        """
        Initialize Frida Engine

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
        self.scripts: Dict[str, frida.core.Script] = {}
        self.running = False

        # Message handlers
        self.message_handlers: List[Callable[[HookEvent], None]] = []
        self.default_handler = self._default_message_handler

        # Statistics
        self.stats = {
            'hooks_triggered': 0,
            'errors': 0,
            'warnings': 0,
            'start_time': None
        }

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
            self.stats['start_time'] = datetime.now()
            return True

        except frida.ProcessNotFoundError:
            self.logger.error(f"Process not found: {self.package_name}")
            return False
        except Exception as e:
            self.logger.error(f"Failed to attach: {e}")
            return False

    def detach(self):
        """Detach from the target process"""
        self.stop_all_scripts()

        if self.session:
            try:
                self.session.detach()
            except:
                pass
            self.session = None

        self.logger.info("Detached")

    def load_script(self, script_code: str, script_name: str = "hook") -> bool:
        """
        Load and execute a Frida script

        Args:
            script_code: JavaScript code to execute
            script_name: Name identifier for the script

        Returns:
            bool: True if loaded successfully
        """
        if not self.session:
            self.logger.error("Not attached to any process. Call attach() first.")
            return False

        try:
            # Unload existing script with same name
            if script_name in self.scripts:
                self.unload_script(script_name)

            # Create and load script
            script = self.session.create_script(script_code)
            script.on('message', self._on_message)
            script.load()

            self.scripts[script_name] = script
            self.logger.info(f"Loaded script: {script_name}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to load script '{script_name}': {e}")
            self.stats['errors'] += 1
            return False

    def unload_script(self, script_name: str) -> bool:
        """
        Unload a script

        Args:
            script_name: Name of the script to unload

        Returns:
            bool: True if unloaded successfully
        """
        if script_name not in self.scripts:
            self.logger.warning(f"Script not found: {script_name}")
            return False

        try:
            script = self.scripts[script_name]
            script.unload()
            del self.scripts[script_name]
            self.logger.info(f"Unloaded script: {script_name}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to unload script '{script_name}': {e}")
            return False

    def reload_script(self, script_code: str, script_name: str = "hook") -> bool:
        """
        Reload a script (hot reload)

        Args:
            script_code: New JavaScript code
            script_name: Name of the script to reload

        Returns:
            bool: True if reloaded successfully
        """
        self.logger.info(f"Reloading script: {script_name}")
        return self.load_script(script_code, script_name)

    def stop_all_scripts(self):
        """Stop and unload all scripts"""
        for script_name in list(self.scripts.keys()):
            self.unload_script(script_name)

    def add_message_handler(self, handler: Callable[[HookEvent], None]):
        """
        Add a custom message handler

        Args:
            handler: Callback function that receives HookEvent
        """
        self.message_handlers.append(handler)

    def remove_message_handler(self, handler: Callable[[HookEvent], None]):
        """
        Remove a message handler

        Args:
            handler: Handler to remove
        """
        if handler in self.message_handlers:
            self.message_handlers.remove(handler)

    def _on_message(self, message: Dict[str, Any], data: Optional[bytes]):
        """
        Internal message handler called by Frida

        Args:
            message: Message from Frida script
            data: Optional binary data
        """
        try:
            if message['type'] == 'send':
                payload = message['payload']

                # Create hook event
                event = HookEvent(
                    timestamp=payload.get('timestamp', datetime.now().isoformat()),
                    thread_id=payload.get('threadId', 0),
                    event_type=payload.get('type', 'unknown'),
                    data=payload
                )

                # Update stats
                if event.event_type == 'hook':
                    self.stats['hooks_triggered'] += 1
                elif event.event_type == 'error':
                    self.stats['errors'] += 1
                elif event.event_type == 'warning':
                    self.stats['warnings'] += 1

                # Call custom handlers
                for handler in self.message_handlers:
                    try:
                        handler(event)
                    except Exception as e:
                        self.logger.error(f"Error in message handler: {e}")

                # Call default handler if no custom handlers
                if not self.message_handlers:
                    self.default_handler(event)

            elif message['type'] == 'error':
                self.logger.error(f"Script error: {message.get('description', 'Unknown error')}")
                self.logger.error(f"Stack: {message.get('stack', 'No stack trace')}")
                self.stats['errors'] += 1

        except Exception as e:
            self.logger.error(f"Error processing message: {e}")

    def _default_message_handler(self, event: HookEvent):
        """
        Default message handler that logs events

        Args:
            event: Hook event
        """
        if event.event_type == 'hook':
            # Format hook event
            stage = event.data.get('stage', 'enter')
            class_name = event.data.get('className', '')
            method_name = event.data.get('methodName', '')
            function_name = event.data.get('function', '')
            module_name = event.data.get('module', '')

            if class_name and method_name:
                # Java hook
                self.logger.info(f"[{stage}] {class_name}.{method_name}")
                if 'arguments' in event.data and stage == 'enter':
                    for i, arg in enumerate(event.data['arguments']):
                        self.logger.info(f"  arg[{i}]: {arg}")
                if 'returnValue' in event.data and stage == 'leave':
                    self.logger.info(f"  return: {event.data['returnValue']}")
            elif function_name:
                # Native hook
                location = f"{module_name}!" if module_name else ""
                self.logger.info(f"[{stage}] {location}{function_name}")
                if 'arguments' in event.data and stage == 'enter':
                    for arg in event.data['arguments']:
                        idx = arg.get('index', 0)
                        self.logger.info(f"  arg[{idx}]: {arg}")
                if 'returnValue' in event.data and stage == 'leave':
                    self.logger.info(f"  return: {event.data['returnValue']}")

        elif event.event_type == 'info':
            self.logger.info(event.data.get('message', str(event.data)))

        elif event.event_type == 'error':
            self.logger.error(event.data.get('message', str(event.data)))

        elif event.event_type == 'warning':
            self.logger.warning(event.data.get('message', str(event.data)))

    def run(self, duration: Optional[int] = None):
        """
        Run the engine and process messages

        Args:
            duration: How long to run in seconds (None = indefinite)
        """
        self.running = True

        # Setup signal handler for graceful shutdown
        def signal_handler(sig, frame):
            self.logger.info("\nStopping hooking session...")
            self.running = False

        signal.signal(signal.SIGINT, signal_handler)

        self.logger.info("Hooking session started. Press Ctrl+C to stop.")

        start_time = time.time()
        try:
            while self.running:
                time.sleep(0.1)

                # Check duration
                if duration and (time.time() - start_time) >= duration:
                    self.logger.info(f"Duration limit reached ({duration}s)")
                    break

        except KeyboardInterrupt:
            self.logger.info("Interrupted by user")

        finally:
            self.running = False
            self._print_stats()

    def _print_stats(self):
        """Print session statistics"""
        if self.stats['start_time']:
            duration = (datetime.now() - self.stats['start_time']).total_seconds()
            self.logger.info("\n=== Hooking Session Statistics ===")
            self.logger.info(f"Duration: {duration:.1f}s")
            self.logger.info(f"Hooks Triggered: {self.stats['hooks_triggered']}")
            self.logger.info(f"Errors: {self.stats['errors']}")
            self.logger.info(f"Warnings: {self.stats['warnings']}")

    def get_stats(self) -> Dict[str, Any]:
        """
        Get session statistics

        Returns:
            Dict[str, Any]: Statistics dictionary
        """
        stats = self.stats.copy()
        if stats['start_time']:
            stats['duration'] = (datetime.now() - stats['start_time']).total_seconds()
        return stats


def create_hook_session(
    frida_device,
    package_name: str,
    spawn: bool = False
) -> Optional[FridaEngine]:
    """
    Convenience function to create a hooking session

    Args:
        frida_device: Frida device object
        package_name: Target package name
        spawn: Spawn the app instead of attaching

    Returns:
        Optional[FridaEngine]: Engine instance or None if failed
    """
    engine = FridaEngine(frida_device, package_name)

    if not engine.attach(spawn=spawn):
        return None

    return engine
