#!/usr/bin/env python3
"""
Hook Templates Module - Frida 스크립트 템플릿 관리 모듈

Frida 스크립트 템플릿을 로드하고 동적으로 변수 치환하여 후킹 스크립트를 생성합니다.

## 구현 방식:
1. **템플릿 파일 관리**: frida_scripts/templates/ 디렉토리에서 .js 파일 로드
2. **변수 치환**: 템플릿 내 플레이스홀더를 실제 값으로 대체
3. **캐싱**: 한 번 로드한 템플릿은 메모리에 캐싱
4. **타입별 생성기**: Java, Native, JNI 각각의 생성 함수

## 템플릿 변수 예시:
### Java Hook:
- CLASS_NAME: com.example.MainActivity
- METHOD_NAME: onCreate
- OVERLOAD_INDEX: -1 (모든 오버로드) 또는 0, 1, 2...
- LOG_ARGS, LOG_RETURN, LOG_BACKTRACE: true/false

### Native Hook:
- MODULE_NAME: libnative-lib.so 또는 null
- FUNCTION_NAME: decrypt
- LOG_ARGS, LOG_RETURN, LOG_REGISTERS, LOG_BACKTRACE: true/false
- ARG_COUNT: 4 (로깅할 인자 개수)

## 개선 예정:
- TODO: 템플릿 문법 검증 (Jinja2 스타일 등)
- TODO: 조건부 블록 (if-else 템플릿 문법)
- TODO: 템플릿 상속 (base 템플릿 + 확장)
- TODO: 커스텀 필터 함수 (값 변환)
- TODO: 템플릿 버전 관리
"""

import logging
from pathlib import Path
from typing import Dict, Optional, List
from dataclasses import dataclass


@dataclass
class HookConfig:
    """
    후킹 설정을 저장하는 데이터 클래스

    ## Java 후킹 설정:
    - class_name: 클래스 이름 (예: com.example.MainActivity)
    - method_name: 메서드 이름 (예: onCreate)
    - overload_index: 오버로드 인덱스
      - -1: 모든 오버로드 후킹
      - 0, 1, 2...: 특정 오버로드만 후킹

    ## Native 후킹 설정:
    - module_name: 모듈 이름 (예: libnative-lib.so)
      - None이면 모든 모듈 검색
    - function_name: 함수 이름 (예: decrypt)
    - function_address: 함수 주소 (예: "0x12345")
      - 설정 시 function_name 무시

    ## 로깅 옵션:
    - log_args: 인자 로깅 (기본: True)
    - log_return: 리턴값 로깅 (기본: True)
    - log_backtrace: 백트레이스 로깅 (기본: False)
    - log_registers: 레지스터 로깅 (Native 전용, 기본: False)

    ## Native 전용:
    - arg_count: 로깅할 인자 개수 (기본: 4)
      - ARM64: x0-x3, ARM: r0-r3 등
    """
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
    Frida 스크립트 템플릿 관리자

    ## 주요 기능:
    1. **템플릿 로드**: .js 템플릿 파일 읽기 및 캐싱
    2. **변수 치환**: 플레이스홀더를 실제 값으로 대체
    3. **스크립트 생성**: Java/Native 후킹 스크립트 동적 생성

    ## 템플릿 치환 방식:
    간단한 문자열 대체 (str.replace)
    ```javascript
    // 템플릿 (java_hook.js)
    var clazz = Java.use("CLASS_NAME");
    clazz.METHOD_NAME.overload(...).implementation = function() { ... };

    // 치환 후
    var clazz = Java.use("com.example.MainActivity");
    clazz.onCreate.overload(...).implementation = function() { ... };
    ```

    ## 캐싱:
    - 파일 I/O 최소화를 위해 메모리 캐싱
    - clear_cache()로 캐시 무효화 가능

    ## TODO:
    - Jinja2 같은 템플릿 엔진 도입 (조건문, 반복문)
    - 사용자 정의 템플릿 디렉토리 지원
    - 템플릿 핫 리로드 (파일 변경 감지)
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
        Java 메서드 후킹 스크립트 생성

        Args:
            config: 후킹 설정

        Returns:
            Optional[str]: 생성된 스크립트 또는 실패 시 None

        ## 동작 과정:
        1. 필수 파라미터 검증 (class_name, method_name)
        2. java_hook.js 템플릿 로드
        3. 변수 치환 딕셔너리 구성
        4. str.replace()로 플레이스홀더 대체

        ## 치환 변수:
        - CLASS_NAME: Java 클래스 전체 경로
        - METHOD_NAME: 메서드 이름
        - OVERLOAD_INDEX: -1 (전체) 또는 특정 인덱스
        - LOG_ARGS, LOG_RETURN, LOG_BACKTRACE: boolean

        ## 예시:
        ```python
        config = HookConfig(
            class_name="com.example.MainActivity",
            method_name="onCreate",
            overload_index=-1,  # 모든 onCreate 후킹
            log_backtrace=True  # 스택 트레이스 출력
        )
        script = manager.generate_java_hook(config)
        ```

        ## TODO:
        - 파라미터 타입 자동 추론 (Reflection 활용)
        - 리턴값 수정 기능 (replace mode)
        - 조건부 후킹 (특정 인자 값일 때만)
        """
        if not config.class_name or not config.method_name:
            self.logger.error("class_name and method_name are required for Java hook")
            return None

        template = self.load_template('java')
        if not template:
            return None

        # Replace template variables (플레이스홀더를 실제 값으로 치환)
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
