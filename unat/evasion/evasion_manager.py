#!/usr/bin/env python3
"""
Evasion Manager Module
Manages anti-detection bypass scripts (Anti-Frida, Anti-Root, Anti-Emulator)
"""

import logging
from pathlib import Path
from typing import List, Optional, Set
from dataclasses import dataclass


@dataclass
class EvasionConfig:
    """Configuration for evasion bypasses"""
    anti_frida: bool = True
    anti_root: bool = True
    anti_emulator: bool = True


class EvasionManager:
    """
    Manages evasion bypass scripts
    Loads and combines anti-detection scripts
    """

    SCRIPT_DIR = Path(__file__).parent.parent.parent / "frida_scripts" / "evasion"

    SCRIPTS = {
        'anti_frida': 'anti_frida_bypass.js',
        'anti_root': 'anti_root_bypass.js',
        'anti_emulator': 'anti_emulator_bypass.js'
    }

    def __init__(self):
        """Initialize evasion manager"""
        self.logger = logging.getLogger(__name__)
        self._script_cache = {}

    def load_script(self, script_type: str) -> Optional[str]:
        """
        Load an evasion script

        Args:
            script_type: Type of script ('anti_frida', 'anti_root', 'anti_emulator')

        Returns:
            Optional[str]: Script content or None if not found
        """
        if script_type in self._script_cache:
            return self._script_cache[script_type]

        if script_type not in self.SCRIPTS:
            self.logger.error(f"Unknown evasion script: {script_type}")
            return None

        script_file = self.SCRIPT_DIR / self.SCRIPTS[script_type]

        if not script_file.exists():
            self.logger.error(f"Evasion script not found: {script_file}")
            return None

        try:
            with open(script_file, 'r', encoding='utf-8') as f:
                content = f.read()
                self._script_cache[script_type] = content
                return content
        except Exception as e:
            self.logger.error(f"Failed to load evasion script {script_file}: {e}")
            return None

    def generate_combined_script(self, config: EvasionConfig) -> Optional[str]:
        """
        Generate a combined evasion script based on configuration

        Args:
            config: Evasion configuration

        Returns:
            Optional[str]: Combined script or None if failed
        """
        scripts = []

        if config.anti_frida:
            script = self.load_script('anti_frida')
            if script:
                scripts.append(script)
                self.logger.info("Added Anti-Frida bypass")

        if config.anti_root:
            script = self.load_script('anti_root')
            if script:
                scripts.append(script)
                self.logger.info("Added Anti-Root bypass")

        if config.anti_emulator:
            script = self.load_script('anti_emulator')
            if script:
                scripts.append(script)
                self.logger.info("Added Anti-Emulator bypass")

        if not scripts:
            self.logger.warning("No evasion scripts selected")
            return None

        # Combine all scripts
        combined = "\n\n// ==========================================\n\n".join(scripts)

        return combined

    def get_available_bypasses(self) -> List[str]:
        """
        Get list of available bypass types

        Returns:
            List[str]: List of bypass type names
        """
        return list(self.SCRIPTS.keys())

    def clear_cache(self):
        """Clear the script cache"""
        self._script_cache.clear()


def create_evasion_script(
    anti_frida: bool = True,
    anti_root: bool = True,
    anti_emulator: bool = True
) -> Optional[str]:
    """
    Convenience function to create an evasion script

    Args:
        anti_frida: Enable Anti-Frida bypass
        anti_root: Enable Anti-Root bypass
        anti_emulator: Enable Anti-Emulator bypass

    Returns:
        Optional[str]: Combined evasion script or None if failed
    """
    config = EvasionConfig(
        anti_frida=anti_frida,
        anti_root=anti_root,
        anti_emulator=anti_emulator
    )

    manager = EvasionManager()
    return manager.generate_combined_script(config)


def get_evasion_help() -> str:
    """
    Get help text for evasion features

    Returns:
        str: Help text
    """
    return """
Evasion Bypass Options:

--anti-frida    : Bypass Frida detection
                 - Named pipe detection
                 - Port scanning (27042)
                 - Library name checks
                 - Thread name detection
                 - /proc checks

--anti-root     : Bypass root detection
                 - su binary checks
                 - Magisk/SuperSU detection
                 - RootBeer library
                 - Build.TAGS checks
                 - Root app package checks

--anti-emulator : Bypass emulator detection
                 - Build properties spoofing
                 - IMEI/Phone number spoofing
                 - Sensor availability
                 - File system artifacts
                 - System property spoofing

--bypass-all    : Enable all bypasses (default)
--no-bypass     : Disable all bypasses
"""
