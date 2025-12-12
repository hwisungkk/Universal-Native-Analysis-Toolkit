#!/usr/bin/env python3
"""
Hook Templates Module
Manages Frida script templates and dynamic script generation
"""

import logging
from pathlib import Path
from typing import Dict, Optional, List
from dataclasses import dataclass


@dataclass
class HookConfig:
    """Configuration for hooking"""
    # Java hooking
    class_name: Optional[str] = None
    method_name: Optional[str] = None
    overload_index: int = -1  # -1 means all overloads

    # Native hooking
    module_name: Optional[str] = None
    function_name: Optional[str] = None
    function_address: Optional[str] = None

    # Logging options
    log_args: bool = True
    log_return: bool = True
    log_backtrace: bool = False
    log_registers: bool = False

    # Native-specific
    arg_count: int = 4


class HookTemplateManager:
    """
    Manages Frida script templates
    Loads templates and performs variable substitution
    """

    TEMPLATE_DIR = Path(__file__).parent.parent.parent / "frida_scripts" / "templates"

    TEMPLATES = {
        'java': 'java_hook.js',
        'native': 'native_hook.js',
        'jni': 'jni_hook.js'
    }

    def __init__(self):
        """Initialize template manager"""
        self.logger = logging.getLogger(__name__)
        self._template_cache: Dict[str, str] = {}

    def load_template(self, template_type: str) -> Optional[str]:
        """
        Load a template file

        Args:
            template_type: Type of template ('java', 'native', 'jni')

        Returns:
            Optional[str]: Template content or None if not found
        """
        if template_type in self._template_cache:
            return self._template_cache[template_type]

        if template_type not in self.TEMPLATES:
            self.logger.error(f"Unknown template type: {template_type}")
            return None

        template_file = self.TEMPLATE_DIR / self.TEMPLATES[template_type]

        if not template_file.exists():
            self.logger.error(f"Template file not found: {template_file}")
            return None

        try:
            with open(template_file, 'r', encoding='utf-8') as f:
                content = f.read()
                self._template_cache[template_type] = content
                return content
        except Exception as e:
            self.logger.error(f"Failed to load template {template_file}: {e}")
            return None

    def load_custom_template(self, template_path: str) -> Optional[str]:
        """
        Load a custom template from a file path

        Args:
            template_path: Path to custom template file

        Returns:
            Optional[str]: Template content or None if not found
        """
        path = Path(template_path)
        if not path.exists():
            self.logger.error(f"Custom template not found: {template_path}")
            return None

        try:
            with open(path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            self.logger.error(f"Failed to load custom template {template_path}: {e}")
            return None

    def generate_java_hook(self, config: HookConfig) -> Optional[str]:
        """
        Generate Java method hook script

        Args:
            config: Hook configuration

        Returns:
            Optional[str]: Generated script or None if failed
        """
        if not config.class_name or not config.method_name:
            self.logger.error("class_name and method_name are required for Java hook")
            return None

        template = self.load_template('java')
        if not template:
            return None

        # Replace template variables
        replacements = {
            'CLASS_NAME': config.class_name,
            'METHOD_NAME': config.method_name,
            'OVERLOAD_INDEX': str(config.overload_index),
            'LOG_ARGS': 'true' if config.log_args else 'false',
            'LOG_RETURN': 'true' if config.log_return else 'false',
            'LOG_BACKTRACE': 'true' if config.log_backtrace else 'false'
        }

        script = template
        for var, value in replacements.items():
            script = script.replace(var, value)

        return script

    def generate_native_hook(self, config: HookConfig) -> Optional[str]:
        """
        Generate native function hook script

        Args:
            config: Hook configuration

        Returns:
            Optional[str]: Generated script or None if failed
        """
        if not config.function_name and not config.function_address:
            self.logger.error("function_name or function_address is required for native hook")
            return None

        template = self.load_template('native')
        if not template:
            return None

        # Use address if provided, otherwise use name
        function_identifier = config.function_address if config.function_address else config.function_name

        # Module name (can be null for any module)
        module_value = f'"{config.module_name}"' if config.module_name else 'null'

        # Replace template variables
        replacements = {
            'MODULE_NAME': module_value,
            'FUNCTION_NAME': function_identifier,
            'LOG_ARGS': 'true' if config.log_args else 'false',
            'LOG_RETURN': 'true' if config.log_return else 'false',
            'LOG_REGISTERS': 'true' if config.log_registers else 'false',
            'LOG_BACKTRACE': 'true' if config.log_backtrace else 'false',
            'ARG_COUNT': str(config.arg_count)
        }

        script = template
        for var, value in replacements.items():
            script = script.replace(var, value)

        return script

    def generate_hook(self, hook_type: str, config: HookConfig) -> Optional[str]:
        """
        Generate hook script based on type

        Args:
            hook_type: Type of hook ('java', 'native', 'jni')
            config: Hook configuration

        Returns:
            Optional[str]: Generated script or None if failed
        """
        if hook_type == 'java':
            return self.generate_java_hook(config)
        elif hook_type == 'native':
            return self.generate_native_hook(config)
        elif hook_type == 'jni':
            self.logger.error("JNI hooking not yet implemented")
            return None
        else:
            self.logger.error(f"Unknown hook type: {hook_type}")
            return None

    def list_available_templates(self) -> List[str]:
        """
        List all available template types

        Returns:
            List[str]: List of template type names
        """
        return list(self.TEMPLATES.keys())

    def clear_cache(self):
        """Clear the template cache"""
        self._template_cache.clear()


def create_java_hook(
    class_name: str,
    method_name: str,
    overload_index: int = -1,
    log_args: bool = True,
    log_return: bool = True,
    log_backtrace: bool = False
) -> Optional[str]:
    """
    Convenience function to create a Java hook script

    Args:
        class_name: Fully qualified class name
        method_name: Method name
        overload_index: Specific overload index or -1 for all
        log_args: Log arguments
        log_return: Log return value
        log_backtrace: Log backtrace

    Returns:
        Optional[str]: Generated script or None if failed
    """
    config = HookConfig(
        class_name=class_name,
        method_name=method_name,
        overload_index=overload_index,
        log_args=log_args,
        log_return=log_return,
        log_backtrace=log_backtrace
    )

    manager = HookTemplateManager()
    return manager.generate_java_hook(config)


def create_native_hook(
    function_name: str,
    module_name: Optional[str] = None,
    function_address: Optional[str] = None,
    log_args: bool = True,
    log_return: bool = True,
    log_registers: bool = False,
    log_backtrace: bool = False,
    arg_count: int = 4
) -> Optional[str]:
    """
    Convenience function to create a native hook script

    Args:
        function_name: Function name
        module_name: Module name (optional)
        function_address: Function address (optional, overrides function_name)
        log_args: Log arguments
        log_return: Log return value
        log_registers: Log register state
        log_backtrace: Log backtrace
        arg_count: Number of arguments to log

    Returns:
        Optional[str]: Generated script or None if failed
    """
    config = HookConfig(
        function_name=function_name,
        module_name=module_name,
        function_address=function_address,
        log_args=log_args,
        log_return=log_return,
        log_registers=log_registers,
        log_backtrace=log_backtrace,
        arg_count=arg_count
    )

    manager = HookTemplateManager()
    return manager.generate_native_hook(config)
