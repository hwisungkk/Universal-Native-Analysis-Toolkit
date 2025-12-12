#!/usr/bin/env python3
"""
Java Discovery Module
Frida를 사용하여 Android 앱의 Java 클래스 및 메서드를 동적으로 탐색

주요 기능:
- 로드된 Java 클래스 실시간 열거
- 메서드 시그니처 추출
- 난독화 패턴 자동 감지
- 패키지 필터링

구현 방식:
- Frida의 Java.enumerateLoadedClasses() API 사용
- JavaScript 스크립트를 타겟 프로세스에 주입
- 런타임에 클래스 목록 수집 및 분석
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
    """
    Java 클래스 정보를 저장하는 데이터 클래스

    Attributes:
        name: 전체 클래스 이름 (예: com.example.MyClass)
        methods: 메서드 시그니처 목록
        fields: 필드 목록 (TODO: 아직 미구현)
        is_obfuscated: 난독화 여부 (휴리스틱 기반 추정)
        package: 패키지 이름
    """
    name: str
    methods: List[str] = field(default_factory=list)
    fields: List[str] = field(default_factory=list)  # TODO: 필드 정보 추출 미구현
    is_obfuscated: bool = False
    package: str = ""


@dataclass
class JavaDiscoveryResult:
    """
    Discovery 결과를 저장하는 데이터 클래스

    전체 탐색 결과의 통계와 상세 정보를 포함
    """
    package_name: str
    total_classes: int = 0
    total_methods: int = 0
    obfuscated_classes: int = 0
    classes: List[JavaClassInfo] = field(default_factory=list)


class JavaDiscovery:
    """
    Java 클래스 및 메서드 탐색 엔진

    동작 방식:
    1. Frida를 사용하여 타겟 앱 프로세스에 attach
    2. JavaScript 스크립트를 주입하여 Java.enumerateLoadedClasses() 실행
    3. 로드된 모든 클래스 목록을 수집
    4. 각 클래스의 메서드를 getDeclaredMethods()로 열거
    5. 난독화 패턴 매칭으로 난독화 여부 판단

    개선 필요 사항:
    - TODO: 메서드 열거 시 병렬 처리로 성능 개선
    - TODO: 클래스 상속 관계 추적
    - TODO: 어노테이션 정보 추출
    - TODO: 필드 정보 추출
    """

    def __init__(self, frida_device, package_name: str):
        """
        Java Discovery 초기화

        Args:
            frida_device: Frida 디바이스 객체
            package_name: 타겟 앱 패키지 이름

        Raises:
            ImportError: Frida가 설치되지 않은 경우
        """
        if not FRIDA_AVAILABLE:
            raise ImportError("Frida is required but not installed")

        self.logger = logging.getLogger(__name__)
        self.device = frida_device
        self.package_name = package_name
        self.session: Optional[frida.core.Session] = None
        self.script: Optional[frida.core.Script] = None

        # 난독화 탐지 패턴
        # ProGuard, R8, DexGuard 등의 난독화 도구가 생성하는 패턴 매칭
        # TODO: 더 많은 난독화 패턴 추가 (예: 한글, 특수문자, 난수 패턴)
        self.obfuscation_patterns = [
            r'^[a-z]$',  # 단일 문자: a, b, c (ProGuard 기본)
            r'^[a-z]\.[a-z]$',  # 두 개의 단일 문자: a.b
            r'^[a-z0-9]{1,3}$',  # 짧은 이름: ab, o0, l1l
            r'[O0][O0]',  # O0O, 00O 혼동 패턴
            r'[lI1]{2,}',  # l1l, III 혼동 패턴
        ]

    def attach(self, spawn: bool = False) -> bool:
        """
        타겟 프로세스에 attach

        동작 방식:
        - spawn=True: 앱을 새로 실행하고 즉시 attach (초기화 코드 분석 가능)
        - spawn=False: 실행 중인 앱에 attach (기본값, 더 안정적)

        Args:
            spawn: True면 앱 실행 후 attach, False면 실행 중인 앱에 attach

        Returns:
            bool: attach 성공 여부

        개선 필요:
        - TODO: attach 재시도 로직 추가
        - TODO: 여러 프로세스 중 선택 기능 (멀티프로세스 앱 대응)
        """
        try:
            if spawn:
                # 앱을 새로 실행하고 일시정지 상태로 attach
                self.logger.info(f"Spawning {self.package_name}...")
                pid = self.device.spawn([self.package_name])
                self.session = self.device.attach(pid)
                self.device.resume(pid)  # 일시정지 해제
            else:
                # 실행 중인 앱에 attach
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
        클래스 이름이 난독화되었는지 휴리스틱으로 판단

        탐지 방법:
        1. 정규식 패턴 매칭 (단일 문자, 짧은 이름, 혼동 패턴)
        2. 패키지 이름 길이 체크 (매우 짧은 패키지명은 난독화 가능성 높음)

        한계:
        - 휴리스틱 기반이므로 100% 정확하지 않음
        - 의도적으로 짧은 이름을 사용하는 경우 오탐 가능
        - 난독화 도구가 새로운 패턴을 사용하면 탐지 못할 수 있음

        Args:
            class_name: 전체 클래스 이름 (예: com.a.b.C)

        Returns:
            bool: 난독화로 추정되면 True

        개선 필요:
        - TODO: 머신러닝 기반 난독화 탐지
        - TODO: 사전 기반 검사 (영어 단어가 있으면 난독화 아님)
        - TODO: 통계적 분석 (entropy 계산)
        """
        # 클래스 이름의 마지막 부분만 추출 (단순 클래스명)
        parts = class_name.split('.')
        simple_name = parts[-1] if parts else class_name

        # 패턴 매칭으로 난독화 확인
        for pattern in self.obfuscation_patterns:
            if re.search(pattern, simple_name):
                return True

        # 추가 휴리스틱: 매우 짧은 패키지 이름들
        # 예: a.b.c.MyClass → 모든 패키지가 2글자 이하면 난독화 가능성 높음
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
        로드된 Java 클래스 열거

        동작 방식:
        1. enumerate_classes.js 스크립트를 타겟 프로세스에 주입
        2. JavaScript에서 Java.enumerateLoadedClasses() 실행
        3. 모든 로드된 클래스 목록을 Python으로 전송
        4. 필터링 및 난독화 분석 수행

        Args:
            package_filter: 특정 패키지만 포함 (기본값: 타겟 앱 패키지)
            include_system: 시스템 클래스 포함 여부 (android.*, java.* 등)
            obfuscated_only: 난독화된 클래스만 반환

        Returns:
            List[JavaClassInfo]: 발견된 클래스 목록

        개선 필요:
        - TODO: 고정된 sleep(2) 대신 동적 대기 (스크립트 완료 시그널 사용)
        - TODO: 점진적 결과 수신 (대량 클래스 처리 시 메모리 효율)
        - TODO: 에러 발생 시 재시도 로직
        """
        if not self.session:
            raise RuntimeError("Not attached to any process. Call attach() first.")

        # 기본값: 타겟 앱 패키지만 필터링
        if package_filter is None and not include_system:
            package_filter = self.package_name

        # Frida 스크립트 로드 (외부 파일 또는 인라인)
        script_path = Path(__file__).parent.parent.parent / "frida_scripts" / "templates" / "enumerate_classes.js"

        if script_path.exists():
            with open(script_path, 'r', encoding='utf-8') as f:
                script_code = f.read()
        else:
            # 폴백: 인라인 스크립트
            script_code = self._get_enumerate_classes_script()

        self.logger.info("Enumerating Java classes...")

        # 스크립트 생성 및 실행
        script = self.session.create_script(script_code)
        classes_data = []

        def on_message(message, data):
            """JavaScript에서 전송한 메시지 수신"""
            if message['type'] == 'send':
                classes_data.append(message['payload'])
            elif message['type'] == 'error':
                self.logger.error(f"Script error: {message['stack']}")

        script.on('message', on_message)
        script.load()

        # 열거 완료 대기
        # TODO: 고정 시간 대신 완료 시그널 기반 대기로 개선 필요
        import time
        time.sleep(2)  # FIXME: 클래스 수가 많으면 2초로 부족할 수 있음

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
