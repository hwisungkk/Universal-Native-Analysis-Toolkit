#!/usr/bin/env python3
"""
Frida Engine Module - Frida 세션 및 스크립트 관리 모듈

Frida 후킹 세션의 생명주기를 관리하고 스크립트 실행 및 메시지 처리를 담당합니다.

## 구현 방식:
1. **세션 관리**: 프로세스 연결/해제, spawn/attach 지원
2. **스크립트 관리**: 다중 스크립트 로드/언로드/핫 리로드
3. **메시지 핸들링**: Frida 스크립트에서 전송한 메시지 처리
4. **이벤트 시스템**: 커스텀 핸들러 등록 및 호출
5. **통계 수집**: 후킹 횟수, 에러, 경고 추적

## 주요 기능:
- **다중 스크립트**: 여러 스크립트 동시 실행 (evasion + hook 등)
- **핫 리로드**: 세션 유지하면서 스크립트만 재로드
- **커스텀 핸들러**: 메시지 처리 로직 확장 가능
- **통계 추적**: 성능 및 디버깅 정보 수집

## 개선 예정:
- TODO: 비동기 메시지 처리 (asyncio)
- TODO: 스크립트 간 통신 (global 변수 공유)
- TODO: 자동 재연결 (세션 끊김 시)
- TODO: 메시지 큐잉 및 배치 처리
- TODO: 스크립트 성능 프로파일링
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
    """
    후킹 이벤트를 나타내는 데이터 클래스

    Attributes:
        timestamp: 이벤트 발생 시각 (ISO 8601 포맷)
        thread_id: 이벤트가 발생한 스레드 ID
        event_type: 이벤트 타입
            - 'hook': 후킹 이벤트 (enter/leave)
            - 'info': 정보 메시지
            - 'error': 에러 메시지
            - 'warning': 경고 메시지
        data: 이벤트 상세 데이터 (함수 이름, 인자, 리턴값 등)

    ## 사용 예시:
    커스텀 핸들러에서 특정 이벤트만 필터링:
    ```python
    def my_handler(event: HookEvent):
        if event.event_type == 'hook':
            if 'decrypt' in event.data.get('methodName', ''):
                # 암호화 관련 메서드만 처리
                pass
    ```
    """
    timestamp: str
    thread_id: int
    event_type: str  # 'hook', 'info', 'error', 'warning'
    data: Dict[str, Any] = field(default_factory=dict)


class FridaEngine:
    """
    Frida Engine - 후킹 세션 관리 클래스

    ## 주요 역할:
    1. **세션 생명주기 관리**:
       - attach(): 프로세스 연결
       - detach(): 연결 해제
       - run(): 메시지 루프 실행

    2. **스크립트 관리**:
       - load_script(): 스크립트 로드 및 실행
       - unload_script(): 스크립트 언로드
       - reload_script(): 핫 리로드

    3. **메시지 처리**:
       - _on_message(): Frida 메시지 수신
       - 커스텀 핸들러 체인 실행
       - 기본 핸들러로 로깅

    ## 다중 스크립트 관리:
    scripts 딕셔너리로 여러 스크립트 동시 관리
    ```python
    engine.load_script(evasion_code, "evasion")
    engine.load_script(hook_code, "main_hook")
    engine.load_script(tracer_code, "tracer")
    ```

    ## TODO:
    - 스크립트 우선순위 시스템
    - 스크립트 간 의존성 관리
    - 메모리 사용량 모니터링
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
                self.logger.info(f"Attaching to {self.package_name}.")

                target = self.package_name.strip()
                
                # 1) 숫자로 입력받으면 PID로 attach
                if isinstance(target, str) and target.isdigit():
                    target_pid = int(target)
                    self.session = self.device.attach(target_pid)

                else:
                    # 2) 먼저 "이름 그대로" 매칭되는 프로세스가 있으면 그 PID로 attach
                    try:
                        procs = self.device.enumerate_processes()
                    except Exception:
                        procs = []

                    exact = [p for p in procs if p.name == target]
                    prefix = [p for p in procs if isinstance(target, str) and p.name.startswith(target + ":")]
                    starts = [p for p in procs if isinstance(target, str) and p.name.startswith(target)]

                    candidates = exact or prefix or starts

                    if candidates:
                     
                        best = None
                        for p in candidates:
                            if ":" not in p.name:
                                best = p
                                break
                        if best is None:
                            best = candidates[0]

                        self.logger.info(f"Resolved attach target: pid={best.pid} name={best.name}")
                        self.session = self.device.attach(best.pid)
                    else:
                        # 3) 마지막 fallback: 프리다 내부 매칭에 맡김(기존 동작)
                        self.session = self.device.attach(target)


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
        Frida 스크립트 로드 및 실행

        Args:
            script_code: 실행할 JavaScript 코드
            script_name: 스크립트 식별자 (다중 스크립트 관리용)

        Returns:
            bool: 로드 성공 시 True

        ## 동작 과정:
        1. 세션 연결 확인 (attach() 먼저 호출 필요)
        2. 동일 이름의 기존 스크립트 언로드 (있다면)
        3. session.create_script()로 스크립트 생성
        4. script.on('message', handler)로 메시지 핸들러 등록
        5. script.load()로 스크립트 실행
        6. scripts 딕셔너리에 저장

        ## 다중 스크립트 활용:
        ```python
        # Evasion 스크립트 먼저 로드
        engine.load_script(evasion_code, "evasion")
        # 메인 후킹 스크립트 로드
        engine.load_script(hook_code, "main")
        # 나중에 main만 재로드 가능
        engine.reload_script(new_hook_code, "main")
        ```

        ## TODO:
        - 스크립트 문법 검증 (load 전에)
        - 스크립트 크기 제한 (메모리 보호)
        - 의존성 자동 주입 (공통 헬퍼 함수 등)
        """
        if not self.session:
            self.logger.error("Not attached to any process. Call attach() first.")
            return False

        try:
            # Unload existing script with same name (핫 리로드 준비)
            if script_name in self.scripts:
                self.unload_script(script_name)

            # Create and load script
            script = self.session.create_script(script_code)
            script.on('message', self._on_message)  # 메시지 핸들러 등록
            script.load()  # 스크립트 실행 (Java.perform() 등이 이 시점에 실행됨)

            self.scripts[script_name] = script
            self.logger.info(f"Loaded script: {script_name}")
            return True

        except Exception as e:
            # 문법 오류, 런타임 오류 등
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
        스크립트 핫 리로드

        Args:
            script_code: 새로운 JavaScript 코드
            script_name: 재로드할 스크립트 이름

        Returns:
            bool: 재로드 성공 시 True

        ## 핫 리로드란?
        - 프로세스 연결을 유지한 채로 스크립트만 교체
        - 앱을 재시작하지 않고 후킹 로직 수정 가능
        - 빠른 디버깅 및 실험 가능

        ## 동작 방식:
        1. 기존 스크립트 언로드 (unload_script)
        2. 새 스크립트 로드 (load_script)
        3. 메시지 핸들러는 유지됨

        ## 사용 시나리오:
        - 후킹 로직 수정 후 즉시 적용
        - 다른 메서드 후킹으로 전환
        - 로그 레벨 동적 변경

        ## 주의사항:
        - Java.use()로 캐싱된 클래스는 유지됨
        - Interceptor.attach()한 후킹은 자동 해제됨
        - global 변수는 초기화됨

        ## TODO:
        - 상태 보존 리로드 (특정 변수 유지)
        - 리로드 실패 시 이전 스크립트로 롤백
        """
        self.logger.info(f"Reloading script: {script_name}")
        # load_script에서 자동으로 기존 스크립트 언로드 처리
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
        Frida가 호출하는 내부 메시지 핸들러

        Args:
            message: Frida 스크립트에서 전송한 메시지
            data: 선택적 바이너리 데이터 (send(payload, data) 사용 시)

        ## 메시지 타입:
        1. **'send'**: 스크립트에서 send() 함수로 전송한 데이터
           - payload 필드에 실제 데이터 포함
           - 후킹 이벤트, 정보, 경고 등

        2. **'error'**: 스크립트 실행 중 오류 발생
           - description: 오류 설명
           - stack: 스택 트레이스

        ## 처리 흐름:
        1. 메시지 타입 확인 (send vs error)
        2. HookEvent 객체 생성
        3. 통계 업데이트 (hooks_triggered, errors, warnings)
        4. 커스텀 핸들러 순차 호출
        5. 커스텀 핸들러 없으면 기본 핸들러 호출

        ## 커스텀 핸들러 체인:
        - 여러 핸들러 등록 가능
        - 순서대로 모두 호출됨
        - 한 핸들러 실패해도 다음 핸들러 계속 실행

        ## TODO:
        - 메시지 우선순위 시스템
        - 핸들러 타임아웃 설정
        - 메시지 큐잉 (고속 메시지 처리)
        - 바이너리 데이터 처리 확장
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

                # Update stats (통계 정보 갱신)
                if event.event_type == 'hook':
                    self.stats['hooks_triggered'] += 1
                elif event.event_type == 'error':
                    self.stats['errors'] += 1
                elif event.event_type == 'warning':
                    self.stats['warnings'] += 1

                # Call custom handlers (등록된 모든 핸들러 호출)
                for handler in self.message_handlers:
                    try:
                        handler(event)
                    except Exception as e:
                        # 한 핸들러 실패해도 다른 핸들러는 계속 실행
                        self.logger.error(f"Error in message handler: {e}")

                # Call default handler if no custom handlers
                # 커스텀 핸들러 없으면 기본 로깅 핸들러 사용
                if not self.message_handlers:
                    self.default_handler(event)

            elif message['type'] == 'error':
                # 스크립트 실행 오류 (문법 오류, 런타임 예외 등)
                self.logger.error(f"Script error: {message.get('description', 'Unknown error')}")
                self.logger.error(f"Stack: {message.get('stack', 'No stack trace')}")
                self.stats['errors'] += 1

        except Exception as e:
            # 메시지 처리 자체에서 오류 발생
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
        엔진 실행 및 메시지 처리 루프

        Args:
            duration: 실행 시간 (초), None이면 무한 실행

        ## 동작 방식:
        1. **Signal 핸들러 등록**: Ctrl+C로 우아하게 종료
        2. **메시지 루프**: 0.1초마다 체크 (메시지는 _on_message에서 비동기 처리)
        3. **시간 제한**: duration 설정 시 자동 종료
        4. **통계 출력**: 종료 시 세션 통계 표시

        ## 메시지 처리 흐름:
        - Frida가 백그라운드에서 메시지 수신
        - script.on('message', handler)로 등록된 _on_message가 자동 호출
        - 이 루프는 프로세스를 살려두는 역할

        ## 종료 방법:
        1. **Ctrl+C**: SIGINT 시그널로 우아한 종료
        2. **시간 제한**: duration 파라미터로 자동 종료
        3. **외부 제어**: self.running = False 설정

        ## 사용 예시:
        ```python
        # 무한 실행 (Ctrl+C로 종료)
        engine.run()

        # 60초 실행 후 자동 종료
        engine.run(duration=60)

        # 백그라운드 실행 (별도 스레드)
        import threading
        thread = threading.Thread(target=engine.run)
        thread.start()
        ```

        ## TODO:
        - 주기적 상태 출력 (진행 중인 후킹 통계)
        - 조건부 종료 (특정 이벤트 발생 시)
        - 자동 재연결 (세션 끊김 감지)
        - 메모리 사용량 모니터링
        """
        self.running = True

        # Setup signal handler for graceful shutdown
        # Ctrl+C (SIGINT) 시그널 핸들러 등록
        def signal_handler(sig, frame):
            self.logger.info("\nStopping hooking session...")
            self.running = False

        signal.signal(signal.SIGINT, signal_handler)

        self.logger.info("Hooking session started. Press Ctrl+C to stop.")

        start_time = time.time()
        try:
            while self.running:
                # 0.1초 슬립 (CPU 사용률 낮춤)
                # 실제 메시지는 Frida가 백그라운드에서 처리
                time.sleep(0.1)

                # Check duration (시간 제한 확인)
                if duration and (time.time() - start_time) >= duration:
                    self.logger.info(f"Duration limit reached ({duration}s)")
                    break

        except KeyboardInterrupt:
            # signal_handler에서 처리되지만 혹시 모를 경우 대비
            self.logger.info("Interrupted by user")

        finally:
            # 정상/비정상 종료 모두 통계 출력
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
