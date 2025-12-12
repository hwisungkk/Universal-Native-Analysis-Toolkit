#!/usr/bin/env python3
"""
UNAT Hooking Module
Provides Frida-based hooking capabilities for Java and native functions
"""

from .frida_engine import FridaEngine, HookEvent, create_hook_session
from .hook_templates import (
    HookTemplateManager,
    HookConfig,
    create_java_hook,
    create_native_hook
)

__all__ = [
    'FridaEngine',
    'HookEvent',
    'create_hook_session',
    'HookTemplateManager',
    'HookConfig',
    'create_java_hook',
    'create_native_hook'
]
