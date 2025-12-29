#!/usr/bin/env python3
"""
APK Handler Module
Handles APK file analysis and information extraction using Androguard
"""

import os
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

try:
    from androguard.core.apk import APK
    from androguard.core.dex import DEX
    ANDROGUARD_AVAILABLE = True
except ImportError:
    ANDROGUARD_AVAILABLE = False
    logging.warning("Androguard not available. APK analysis features will be limited.")


@dataclass
class APKInfo:
    """Data class to store APK information"""
    package_name: str = ""
    app_name: str = ""
    version_name: str = ""
    version_code: str = ""
    min_sdk: str = ""
    target_sdk: str = ""
    permissions: List[str] = field(default_factory=list)
    activities: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    receivers: List[str] = field(default_factory=list)
    providers: List[str] = field(default_factory=list)
    native_libraries: List[str] = field(default_factory=list)
    dex_files: List[str] = field(default_factory=list)
    main_activity: Optional[str] = None
    is_debuggable: bool = False
    file_path: str = ""
    file_size: int = 0


class APKHandler:
    """
    APK Handler for analyzing Android APK files
    Uses Androguard for comprehensive APK analysis
    """

    def __init__(self, apk_path: str):
        """
        Initialize APK Handler

        Args:
            apk_path: Path to the APK file

        Raises:
            FileNotFoundError: If APK file doesn't exist
            ImportError: If Androguard is not available
        """
        self.logger = logging.getLogger(__name__)
        self.apk_path = Path(apk_path)

        if not self.apk_path.exists():
            raise FileNotFoundError(f"APK file not found: {apk_path}")

        if not ANDROGUARD_AVAILABLE:
            raise ImportError("Androguard is required but not installed. Install with: pip install androguard")

        self.logger.info(f"Loading APK: {self.apk_path.name}")
        self.apk: Optional[APK] = None
        self.info: Optional[APKInfo] = None

    def load(self) -> bool:
        """
        Load and parse the APK file

        Returns:
            bool: True if loaded successfully, False otherwise
        """
        try:
            self.apk = APK(str(self.apk_path))
            self.logger.info(f"Successfully loaded APK: {self.apk.get_package()}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to load APK: {e}")
            return False

    def extract_info(self) -> APKInfo:
        """
        Extract comprehensive information from the APK

        Returns:
            APKInfo: Dataclass containing APK information
        """
        if not self.apk:
            if not self.load():
                raise RuntimeError("Failed to load APK")

        self.logger.info("Extracting APK information...")

        info = APKInfo()
        info.file_path = str(self.apk_path)
        info.file_size = self.apk_path.stat().st_size

        # Basic information
        info.package_name = self.apk.get_package() or ""
        info.app_name = self.apk.get_app_name() or ""
        info.version_name = self.apk.get_androidversion_name() or ""
        info.version_code = self.apk.get_androidversion_code() or ""

        # SDK versions
        info.min_sdk = str(self.apk.get_min_sdk_version() or "")
        info.target_sdk = str(self.apk.get_target_sdk_version() or "")

        # Permissions
        info.permissions = self.apk.get_permissions() or []

        # Components
        info.activities = self.apk.get_activities() or []
        info.services = self.apk.get_services() or []
        info.receivers = self.apk.get_receivers() or []
        info.providers = self.apk.get_providers() or []

        # Main activity
        info.main_activity = self.apk.get_main_activity()

        # Native libraries
        info.native_libraries = self.apk.get_libraries() or []

        # DEX files
        info.dex_files = self.apk.get_dex_names() or []

        # Security flags
        # Check debuggable flag with compatibility for different androguard versions
        try:
            # Try new method first (androguard 4.x)
            info.is_debuggable = self.apk.is_debuggable()
        except AttributeError:
            # Fallback: parse from manifest for newer versions
            try:
                manifest = self.apk.get_android_manifest_axml()
                app_element = manifest.get_element("application")
                if app_element:
                    debuggable = app_element.get('{http://schemas.android.com/apk/res/android}debuggable')
                    info.is_debuggable = debuggable == 'true' if debuggable else False
                else:
                    info.is_debuggable = False
            except Exception as e:
                self.logger.warning(f"Could not determine debuggable flag: {e}")
                info.is_debuggable = False

        self.info = info
        self.logger.info(f"Extracted info for package: {info.package_name}")

        return info

    def get_manifest_xml(self) -> str:
        """
        Get the AndroidManifest.xml content

        Returns:
            str: Decoded manifest XML content
        """
        if not self.apk:
            if not self.load():
                raise RuntimeError("Failed to load APK")

        return self.apk.get_android_manifest_xml().toprettyxml()

    def get_native_libraries_by_arch(self) -> Dict[str, List[str]]:
        """
        Get native libraries organized by architecture

        Returns:
            Dict[str, List[str]]: Dictionary mapping architecture to library list
        """
        if not self.apk:
            if not self.load():
                raise RuntimeError("Failed to load APK")

        libs_by_arch = {}

        # Get all files in lib/ directory
        for file in self.apk.get_files():
            if file.startswith("lib/"):
                parts = file.split("/")
                if len(parts) >= 3:
                    arch = parts[1]  # e.g., arm64-v8a, armeabi-v7a
                    lib_name = parts[2]

                    if arch not in libs_by_arch:
                        libs_by_arch[arch] = []
                    libs_by_arch[arch].append(lib_name)

        return libs_by_arch

    def extract_file(self, file_path: str, output_dir: str) -> Optional[str]:
        """
        Extract a specific file from the APK

        Args:
            file_path: Path to file inside APK (e.g., "lib/arm64-v8a/libnative.so")
            output_dir: Directory to extract to

        Returns:
            Optional[str]: Path to extracted file, or None if failed
        """
        if not self.apk:
            if not self.load():
                raise RuntimeError("Failed to load APK")

        try:
            data = self.apk.get_file(file_path)
            if not data:
                self.logger.error(f"File not found in APK: {file_path}")
                return None

            output_path = Path(output_dir) / file_path
            output_path.parent.mkdir(parents=True, exist_ok=True)

            with open(output_path, 'wb') as f:
                f.write(data)

            self.logger.info(f"Extracted: {file_path} -> {output_path}")
            return str(output_path)

        except Exception as e:
            self.logger.error(f"Failed to extract {file_path}: {e}")
            return None

    def extract_all_native_libs(self, output_dir: str) -> Dict[str, str]:
        """
        Extract all native libraries from the APK

        Args:
            output_dir: Directory to extract libraries to

        Returns:
            Dict[str, str]: Dictionary mapping library name to extracted path
        """
        libs_by_arch = self.get_native_libraries_by_arch()
        extracted = {}

        for arch, libs in libs_by_arch.items():
            for lib in libs:
                lib_path = f"lib/{arch}/{lib}"
                extracted_path = self.extract_file(lib_path, output_dir)
                if extracted_path:
                    extracted[lib] = extracted_path

        return extracted

    def get_summary(self) -> str:
        """
        Get a human-readable summary of the APK

        Returns:
            str: Formatted summary string
        """
        if not self.info:
            self.extract_info()

        summary = f"""
APK Analysis Summary
{'='*50}
File: {self.info.file_path}
Size: {self.info.file_size / 1024 / 1024:.2f} MB

Application Information:
  Package: {self.info.package_name}
  Name: {self.info.app_name}
  Version: {self.info.version_name} ({self.info.version_code})

SDK Versions:
  Min SDK: {self.info.min_sdk}
  Target SDK: {self.info.target_sdk}

Security:
  Debuggable: {self.info.is_debuggable}

Components:
  Activities: {len(self.info.activities)}
  Services: {len(self.info.services)}
  Receivers: {len(self.info.receivers)}
  Providers: {len(self.info.providers)}
  Main Activity: {self.info.main_activity or 'Not found'}

Permissions: {len(self.info.permissions)}
Native Libraries: {len(self.info.native_libraries)}
DEX Files: {len(self.info.dex_files)}
{'='*50}
"""
        return summary


def analyze_apk(apk_path: str, verbose: bool = False) -> APKInfo:
    """
    Convenience function to analyze an APK file

    Args:
        apk_path: Path to the APK file
        verbose: Print detailed information

    Returns:
        APKInfo: Extracted APK information
    """
    handler = APKHandler(apk_path)
    info = handler.extract_info()

    if verbose:
        print(handler.get_summary())

    return info
