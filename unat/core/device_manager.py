#!/usr/bin/env python3
"""
Device Manager Module
Manages Android device connections via ADB and Frida
"""

import os
import logging
import subprocess
import time
from typing import List, Optional, Dict, Any
from dataclasses import dataclass

try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False
    logging.warning("Frida not available. Dynamic analysis features will be limited.")


@dataclass
class DeviceInfo:
    """Data class to store device information"""
    serial: str
    model: str = "Unknown"
    android_version: str = "Unknown"
    sdk_version: str = "Unknown"
    architecture: str = "Unknown"
    is_emulator: bool = False
    is_rooted: bool = False
    frida_available: bool = False


class DeviceManager:
    """
    Device Manager for handling Android device connections
    Manages both ADB and Frida connections
    """

    def __init__(self, adb_path: str = "adb", device_serial: Optional[str] = None):
        """
        Initialize Device Manager

        Args:
            adb_path: Path to adb executable (default: "adb" from PATH)
            device_serial: Specific device serial to use (None for auto-detect)
        """
        self.logger = logging.getLogger(__name__)
        self.adb_path = adb_path
        self.device_serial = device_serial
        self.device_info: Optional[DeviceInfo] = None
        self.frida_device: Optional[Any] = None

        # Verify ADB is available
        if not self._check_adb():
            raise RuntimeError(f"ADB not found at: {adb_path}")

    def _check_adb(self) -> bool:
        """Check if ADB is available"""
        try:
            result = subprocess.run(
                [self.adb_path, "version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def _run_adb_command(self, command: List[str], timeout: int = 30) -> Optional[str]:
        """
        Run an ADB command

        Args:
            command: ADB command as list of arguments
            timeout: Command timeout in seconds

        Returns:
            Optional[str]: Command output or None if failed
        """
        cmd = [self.adb_path]

        # Add device serial if specified
        if self.device_serial:
            cmd.extend(["-s", self.device_serial])

        cmd.extend(command)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            if result.returncode == 0:
                return result.stdout.strip()
            else:
                self.logger.error(f"ADB command failed: {result.stderr}")
                return None

        except subprocess.TimeoutExpired:
            self.logger.error(f"ADB command timed out: {' '.join(command)}")
            return None
        except Exception as e:
            self.logger.error(f"ADB command error: {e}")
            return None

    def list_devices(self) -> List[str]:
        """
        List all connected Android devices

        Returns:
            List[str]: List of device serials
        """
        output = self._run_adb_command(["devices"])
        if not output:
            return []

        devices = []
        for line in output.split('\n')[1:]:  # Skip first line "List of devices attached"
            if '\t' in line:
                serial = line.split('\t')[0].strip()
                if serial:
                    devices.append(serial)

        self.logger.info(f"Found {len(devices)} device(s)")
        return devices

    def connect(self, serial: Optional[str] = None) -> bool:
        """
        Connect to a specific device or auto-select

        Args:
            serial: Device serial (None for auto-detect)

        Returns:
            bool: True if connected successfully
        """
        if serial:
            self.device_serial = serial

        devices = self.list_devices()

        if not devices:
            self.logger.error("No devices found")
            return False

        if not self.device_serial:
            if len(devices) == 1:
                self.device_serial = devices[0]
                self.logger.info(f"Auto-selected device: {self.device_serial}")
            else:
                self.logger.error(f"Multiple devices found. Please specify one: {devices}")
                return False

        # Verify connection
        if self.device_serial not in devices:
            self.logger.error(f"Device {self.device_serial} not found")
            return False

        # Get device information
        self.device_info = self._get_device_info()

        self.logger.info(f"Connected to device: {self.device_serial}")
        return True

    def _get_device_info(self) -> DeviceInfo:
        """Get detailed device information"""
        if not self.device_serial:
            raise RuntimeError("No device connected")

        info = DeviceInfo(serial=self.device_serial)

        # Get model
        model = self._run_adb_command(["shell", "getprop", "ro.product.model"])
        if model:
            info.model = model

        # Get Android version
        android_ver = self._run_adb_command(["shell", "getprop", "ro.build.version.release"])
        if android_ver:
            info.android_version = android_ver

        # Get SDK version
        sdk_ver = self._run_adb_command(["shell", "getprop", "ro.build.version.sdk"])
        if sdk_ver:
            info.sdk_version = sdk_ver

        # Get architecture
        arch = self._run_adb_command(["shell", "getprop", "ro.product.cpu.abi"])
        if arch:
            info.architecture = arch

        # Check if emulator
        qemu = self._run_adb_command(["shell", "getprop", "ro.kernel.qemu"])
        info.is_emulator = (qemu == "1")

        # Check if rooted (simple check)
        su_check = self._run_adb_command(["shell", "which", "su"])
        info.is_rooted = bool(su_check and "su" in su_check)

        # Check Frida availability
        info.frida_available = self._check_frida()

        return info

    def _check_frida(self) -> bool:
        """Check if Frida server is running on device"""
        if not FRIDA_AVAILABLE:
            return False

        try:
            devices = frida.enumerate_devices()
            for device in devices:
                if self.device_serial and self.device_serial in device.id:
                    self.frida_device = device
                    return True
            return False
        except Exception as e:
            self.logger.debug(f"Frida check failed: {e}")
            return False

    def get_frida_device(self) -> Optional[Any]:
        """
        Get Frida device handle

        Returns:
            Optional[frida.Device]: Frida device or None
        """
        if not FRIDA_AVAILABLE:
            self.logger.error("Frida is not available")
            return None

        if not self.frida_device:
            try:
                # Try to get USB device
                self.frida_device = frida.get_usb_device()
                self.logger.info(f"Connected to Frida device: {self.frida_device.name}")
            except Exception as e:
                self.logger.error(f"Failed to connect to Frida device: {e}")
                return None

        return self.frida_device

    def install_apk(self, apk_path: str, reinstall: bool = False) -> bool:
        """
        Install APK on the device

        Args:
            apk_path: Path to APK file
            reinstall: Whether to reinstall if already installed

        Returns:
            bool: True if installed successfully
        """
        if not os.path.exists(apk_path):
            self.logger.error(f"APK file not found: {apk_path}")
            return False

        cmd = ["install"]
        if reinstall:
            cmd.append("-r")
        cmd.append(apk_path)

        self.logger.info(f"Installing APK: {apk_path}")
        output = self._run_adb_command(cmd, timeout=120)

        if output and "Success" in output:
            self.logger.info("APK installed successfully")
            return True
        else:
            self.logger.error(f"APK installation failed: {output}")
            return False

    def uninstall_package(self, package_name: str) -> bool:
        """
        Uninstall a package from the device

        Args:
            package_name: Package name to uninstall

        Returns:
            bool: True if uninstalled successfully
        """
        self.logger.info(f"Uninstalling package: {package_name}")
        output = self._run_adb_command(["uninstall", package_name])

        if output and "Success" in output:
            self.logger.info("Package uninstalled successfully")
            return True
        else:
            self.logger.error(f"Package uninstall failed: {output}")
            return False

    def start_activity(self, package_name: str, activity_name: Optional[str] = None) -> bool:
        """
        Start an application activity

        Args:
            package_name: Package name
            activity_name: Activity name (None for main activity)

        Returns:
            bool: True if started successfully
        """
        if activity_name:
            component = f"{package_name}/{activity_name}"
        else:
            component = package_name

        cmd = ["shell", "am", "start", "-n", component]
        output = self._run_adb_command(cmd)

        if output and "Error" not in output:
            self.logger.info(f"Started activity: {component}")
            return True
        else:
            self.logger.error(f"Failed to start activity: {output}")
            return False

    def get_running_processes(self) -> List[Dict[str, str]]:
        """
        Get list of running processes

        Returns:
            List[Dict[str, str]]: List of process information
        """
        output = self._run_adb_command(["shell", "ps"])
        if not output:
            return []

        processes = []
        for line in output.split('\n')[1:]:  # Skip header
            parts = line.split()
            if len(parts) >= 9:
                processes.append({
                    "user": parts[0],
                    "pid": parts[1],
                    "name": parts[-1]
                })

        return processes

    def get_device_summary(self) -> str:
        """
        Get a human-readable summary of the device

        Returns:
            str: Formatted summary string
        """
        if not self.device_info:
            return "No device connected"

        summary = f"""
Device Information
{'='*50}
Serial: {self.device_info.serial}
Model: {self.device_info.model}
Android Version: {self.device_info.android_version} (SDK {self.device_info.sdk_version})
Architecture: {self.device_info.architecture}
Emulator: {self.device_info.is_emulator}
Rooted: {self.device_info.is_rooted}
Frida Available: {self.device_info.frida_available}
{'='*50}
"""
        return summary


def connect_device(adb_path: str = "adb", serial: Optional[str] = None) -> Optional[DeviceManager]:
    """
    Convenience function to connect to a device

    Args:
        adb_path: Path to adb executable
        serial: Device serial (None for auto-detect)

    Returns:
        Optional[DeviceManager]: Device manager instance or None if failed
    """
    try:
        manager = DeviceManager(adb_path=adb_path)
        if manager.connect(serial):
            return manager
        return None
    except Exception as e:
        logging.error(f"Failed to connect to device: {e}")
        return None
