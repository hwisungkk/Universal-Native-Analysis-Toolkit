#!/usr/bin/env python3
"""
JNI Discovery Module - JNI 함수 동적 탐지 모듈

Java Native Interface(JNI) 함수와 RegisterNatives 호출을 런타임에 탐지합니다.

## 구현 방식:
1. **Frida 동적 계측**: 앱 실행 중 JNI 브릿지 후킹
2. **RegisterNatives 가로채기**:
   - JNI_OnLoad에서 호출되는 RegisterNatives 후킹
   - JNINativeMethod 구조체 파싱하여 메서드 정보 추출
3. **Native 메서드 열거**:
   - Java.enumerateLoadedClasses()로 모든 클래스 순회
   - getDeclaredMethods()로 native 메서드 탐지

## JNI 브릿지 탐지 방법:
### 1. Static JNI (자동 링킹):
   - 함수 이름 규칙: Java_<package>_<class>_<method>
   - 예: Java_com_example_MainActivity_nativeMethod
   - Native Discovery로 심볼 테이블에서 탐지 가능

### 2. Dynamic JNI (RegisterNatives):
   - JNI_OnLoad에서 RegisterNatives 호출
   - 임의의 함수 이름을 Java 메서드에 매핑
   - 심볼 테이블만으로는 탐지 불가 → 런타임 후킹 필요

## RegisterNatives 구조체:
```c
typedef struct {
    char* name;        // Java 메서드 이름
    char* signature;   // JNI 시그니처 (예: "(I)V")
    void* fnPtr;       // Native 함수 포인터
} JNINativeMethod;
```

## 개선 예정:
- TODO: JNI 호출 추적 (Java → Native 호출 흐름)
- TODO: JNI 시그니처 파싱 (파라미터 타입 추출)
- TODO: JNI 함수 자동 후킹 설정 생성
- TODO: 메모리 누수 탐지 (NewGlobalRef 추적)
- TODO: JNI 예외 처리 추적
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
    """
    JNI Native 메서드 정보를 저장하는 데이터 클래스

    Attributes:
        class_name: Java 클래스 이름 (예: com.example.MainActivity)
        method_name: Java 메서드 이름 (예: nativeMethod)
        signature: JNI 시그니처 (예: "(I)V" = int 파라미터, void 리턴)
        address: Native 함수 주소 (RegisterNatives에서 추출)
        is_registered: RegisterNatives로 등록되었는지 여부
                      - True: Dynamic JNI (RegisterNatives 사용)
                      - False: Static JNI (자동 링킹)

    ## JNI 시그니처 예시:
    - "()V": void method()
    - "(I)I": int method(int)
    - "(Ljava/lang/String;)Z": boolean method(String)
    - "([B)[B": byte[] method(byte[])
    """
    class_name: str
    method_name: str
    signature: str
    address: Optional[str] = None
    is_registered: bool = False  # True if found via RegisterNatives


@dataclass
class JNIRegistration:
    """
    RegisterNatives 호출 정보를 저장하는 데이터 클래스

    Attributes:
        class_name: 메서드를 등록하는 Java 클래스
        method_count: 등록된 메서드 개수
        methods: 등록된 메서드 목록 (name, signature, address)
        timestamp: 등록 시각 (ISO 8601 포맷)

    ## 분석 활용:
    - 한 번에 여러 메서드 등록하는 패턴 확인
    - 런타임에 동적으로 변경되는 JNI 매핑 추적
    - 난독화된 Native 함수와 Java 메서드 연결
    """
    class_name: str
    method_count: int
    methods: List[Dict[str, str]] = field(default_factory=list)
    timestamp: str = ""


@dataclass
class JNIDiscoveryResult:
    """
    JNI Discovery 전체 결과를 저장하는 데이터 클래스

    Attributes:
        package_name: 분석한 앱 패키지 이름
        total_native_methods: 발견된 Native 메서드 총 개수
        total_registrations: RegisterNatives 호출 총 개수
        native_methods: Native 메서드 상세 목록
        registrations: RegisterNatives 호출 상세 목록
    """
    package_name: str
    total_native_methods: int = 0
    total_registrations: int = 0
    native_methods: List[JNINativeMethod] = field(default_factory=list)
    registrations: List[JNIRegistration] = field(default_factory=list)


class JNIDiscovery:
    """
    JNI Discovery - JNI 함수 동적 탐지 클래스

    ## 탐지 방식:
    Frida를 사용하여 런타임에 JNI 브릿지를 후킹하고 분석

    ## 주요 기능:
    1. **RegisterNatives 가로채기**:
       - Interceptor.attach()로 RegisterNatives 후킹
       - JNINativeMethod 배열 파싱
       - 함수 이름, 시그니처, 주소 추출

    2. **Native 메서드 열거**:
       - Java Reflection으로 모든 클래스 순회
       - native 키워드가 있는 메서드 탐지
       - 메서드 시그니처 추출

    3. **동적 vs 정적 JNI 구분**:
       - RegisterNatives로 등록 = Dynamic JNI
       - 자동 링킹 = Static JNI

    ## 기술적 세부사항:
    - JNINativeMethod 구조체 크기:
      - 32비트: 12바이트 (4 + 4 + 4)
      - 64비트: 24바이트 (8 + 8 + 8)
    - 포인터 읽기: Process.pointerSize로 아키텍처 자동 대응

    ## TODO:
    - JNI 호출 추적 (onEnter/onLeave로 호출 흐름 기록)
    - JNI 시그니처 완전 파싱 (타입 추출 및 검증)
    - JNI 예외 추적 (ExceptionCheck/ExceptionClear)
    - NewGlobalRef 추적으로 메모리 누수 탐지
    """

    def __init__(self, frida_device, package_name: str):
        """
        JNI Discovery 초기화

        Args:
            frida_device: Frida 디바이스 객체 (USB/Emulator)
            package_name: 분석 대상 패키지 이름

        Raises:
            ImportError: Frida가 설치되지 않은 경우

        ## 초기화 단계:
        1. Frida 가용성 확인
        2. 디바이스 및 패키지 정보 저장
        3. 세션 및 스크립트 핸들 초기화
        4. 결과 저장용 리스트 초기화
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
        대상 프로세스에 연결

        Args:
            spawn: True면 앱 새로 실행, False면 실행 중인 프로세스에 연결

        Returns:
            bool: 연결 성공 시 True

        ## Spawn vs Attach:
        ### Spawn (spawn=True):
        - 앱을 새로 시작하고 즉시 연결
        - JNI_OnLoad 시점부터 후킹 가능
        - RegisterNatives 호출 100% 캡처
        - 초기 로딩 시점 분석에 유리

        ### Attach (spawn=False):
        - 이미 실행 중인 앱에 연결
        - 연결 시점 이전의 RegisterNatives는 놓침
        - 실시간 분석에 유리
        - 앱 재시작 불필요

        ## 권장:
        - JNI 탐지는 spawn=True 권장 (초기화 코드 분석)
        - 런타임 후킹은 spawn=False 가능
        """
        try:
            if spawn:
                self.logger.info(f"Spawning {self.package_name}...")
                # 앱을 중단 상태로 시작
                pid = self.device.spawn([self.package_name])
                # 프로세스에 연결
                self.session = self.device.attach(pid)
                # 프로세스 재개 (JNI_OnLoad가 이 시점에 실행됨)
                self.device.resume(pid)
            else:
                self.logger.info(f"Attaching to {self.package_name}...")
                # 실행 중인 프로세스에 연결
                self.session = self.device.attach(self.package_name)

            self.logger.info("Attached successfully")
            return True

        except frida.ProcessNotFoundError:
            self.logger.error(f"Process not found: {self.package_name}")
            self.logger.error("앱이 실행 중인지 확인하거나 spawn=True 옵션을 사용하세요")
            return False
        except Exception as e:
            self.logger.error(f"Failed to attach: {e}")
            return False

    def detach(self):
        """
        대상 프로세스에서 연결 해제

        ## 정리 순서:
        1. 스크립트 언로드 (후킹 해제)
        2. 세션 종료 (프로세스 연결 해제)
        3. 핸들 초기화

        ## 참고:
        - detach 후에도 앱은 계속 실행됨
        - 후킹이 해제되어 원래 동작으로 복귀
        """
        if self.script:
            self.script.unload()
            self.script = None

        if self.session:
            self.session.detach()
            self.session = None

        self.logger.info("Detached")

    def discover(self, timeout: int = 5) -> JNIDiscoveryResult:
        """
        JNI 탐지 수행

        Args:
            timeout: 탐지 대기 시간 (초)

        Returns:
            JNIDiscoveryResult: JNI 탐지 결과

        ## 탐지 프로세스:
        1. **스크립트 로드**:
           - jni_discovery.js 파일 읽기
           - 파일 없으면 fallback 스크립트 사용

        2. **RegisterNatives 후킹**:
           - JNI_OnLoad에서 호출되는 RegisterNatives 가로채기
           - JNINativeMethod 배열 파싱
           - 각 메서드의 name, signature, fnPtr 추출

        3. **Native 메서드 열거**:
           - Java.enumerateLoadedClasses()로 모든 클래스 순회
           - getDeclaredMethods()로 메서드 목록 획득
           - Modifier.isNative()로 native 메서드 필터링

        4. **메시지 처리**:
           - jni_register: RegisterNatives 호출 정보
           - native_method: 열거로 발견한 Native 메서드
           - jni_summary: 최종 요약 정보

        ## 타이밍:
        - timeout은 앱 초기화 시간을 고려하여 설정
        - 복잡한 앱은 10초 이상 권장
        - RegisterNatives는 보통 JNI_OnLoad에서 즉시 호출됨

        ## TODO:
        - 비동기 메시지 처리로 타임아웃 개선
        - 진행 상황 실시간 출력
        - 중복 메서드 제거 로직
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
            """
            Frida 메시지 핸들러

            ## 메시지 타입:
            - send: 스크립트에서 전송한 데이터
            - error: 스크립트 실행 오류
            """
            if message['type'] == 'send':
                payload = message['payload']
                msg_type = payload.get('type')

                if msg_type == 'jni_register':
                    # RegisterNatives call detected (Dynamic JNI)
                    registration = JNIRegistration(
                        class_name=payload.get('className', '<unknown>'),
                        method_count=payload.get('methodCount', 0),
                        methods=payload.get('methods', []),
                        timestamp=payload.get('timestamp', '')
                    )
                    self.registrations.append(registration)

                    # Also add to native methods list with is_registered=True
                    for method in payload.get('methods', []):
                        native_method = JNINativeMethod(
                            class_name=payload.get('className', '<unknown>'),
                            method_name=method.get('name', ''),
                            signature=method.get('signature', ''),
                            address=method.get('address', ''),
                            is_registered=True  # Dynamic JNI
                        )
                        self.native_methods.append(native_method)

                elif msg_type == 'native_method':
                    # Native method found via enumeration (Static or Dynamic)
                    native_method = JNINativeMethod(
                        class_name=payload.get('className', ''),
                        method_name=payload.get('methodName', ''),
                        signature=payload.get('signature', ''),
                        is_registered=False  # 열거로 발견 (주소는 모름)
                    )
                    self.native_methods.append(native_method)

                elif msg_type == 'jni_summary':
                    # Final summary from script
                    self.logger.info(
                        f"JNI Discovery complete: {payload.get('totalNativeMethods', 0)} "
                        f"native methods, {payload.get('totalRegistrations', 0)} registrations"
                    )

            elif message['type'] == 'error':
                self.logger.error(f"Script error: {message.get('description', 'Unknown error')}")

        script.on('message', on_message)
        script.load()

        # Wait for discovery to complete
        # RegisterNatives는 JNI_OnLoad에서 즉시 호출됨
        # 클래스 열거는 2초 후 시작 (스크립트 내 setTimeout)
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
