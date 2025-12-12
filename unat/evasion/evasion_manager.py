#!/usr/bin/env python3
"""
Evasion Manager Module - 탐지 우회 스크립트 관리 모듈

Anti-Frida, Anti-Root, Anti-Emulator 우회 스크립트를 로드하고 결합합니다.

## 구현 방식:
1. **개별 스크립트 로드**: frida_scripts/evasion/ 디렉토리에서 우회 스크립트 읽기
2. **선택적 활성화**: 필요한 우회만 선택적으로 활성화
3. **스크립트 결합**: 여러 우회 스크립트를 하나로 병합
4. **캐싱**: 한 번 로드한 스크립트 재사용

## 우회 스크립트 종류:
### Anti-Frida (anti_frida_bypass.js):
- Named pipe 탐지 우회 (/dev/socket/linjector)
- 포트 스캔 우회 (27042, 27043 포트)
- 라이브러리 이름 체크 우회 (frida-agent, frida-gadget)
- /proc 파일 시스템 우회
- strstr/strcmp 후킹 (문자열 비교 조작)

### Anti-Root (anti_root_bypass.js):
- su 바이너리 체크 우회 (30+ 경로)
- Magisk/SuperSU 탐지 우회
- RootBeer 라이브러리 우회
- Build.TAGS 조작 (test-keys → release-keys)
- Root 앱 패키지 체크 우회

### Anti-Emulator (anti_emulator_bypass.js):
- Build 속성 스푸핑 (Samsung Galaxy S21로 위장)
- IMEI/전화번호 스푸핑
- 센서 가용성 조작
- 에뮬레이터 파일 숨김 (qemud, goldfish 등)
- SystemProperties 조작

## 사용 시나리오:
```python
# 모든 우회 활성화
config = EvasionConfig(anti_frida=True, anti_root=True, anti_emulator=True)

# Frida 탐지만 우회
config = EvasionConfig(anti_frida=True, anti_root=False, anti_emulator=False)

# 우회 없음 (순수 후킹만)
config = EvasionConfig(anti_frida=False, anti_root=False, anti_emulator=False)
```

## 개선 예정:
- TODO: SSL Pinning 우회 추가
- TODO: Integrity Check 우회 (앱 변조 탐지)
- TODO: 안티 디버깅 우회 (ptrace, TracerPid 등)
- TODO: Obfuscation 우회 (난독화 해제)
- TODO: 커스텀 우회 스크립트 지원
"""

import logging
from pathlib import Path
from typing import List, Optional, Set
from dataclasses import dataclass


@dataclass
class EvasionConfig:
    """
    우회 설정을 저장하는 데이터 클래스

    Attributes:
        anti_frida: Frida 탐지 우회 활성화 (기본: True)
        anti_root: Root 탐지 우회 활성화 (기본: True)
        anti_emulator: 에뮬레이터 탐지 우회 활성화 (기본: True)

    ## 사용 예시:
    ```python
    # 모든 우회 활성화 (기본)
    config = EvasionConfig()

    # Frida만 우회
    config = EvasionConfig(anti_frida=True, anti_root=False, anti_emulator=False)

    # 우회 없음 (순수 분석)
    config = EvasionConfig(anti_frida=False, anti_root=False, anti_emulator=False)
    ```
    """
    anti_frida: bool = True
    anti_root: bool = True
    anti_emulator: bool = True


class EvasionManager:
    """
    우회 스크립트 관리자

    ## 주요 기능:
    1. **스크립트 로드**: .js 우회 스크립트 읽기 및 캐싱
    2. **스크립트 결합**: 여러 우회 스크립트를 하나로 병합
    3. **선택적 활성화**: 설정에 따라 필요한 우회만 포함

    ## 스크립트 결합 방식:
    각 우회 스크립트를 구분선으로 구분하여 연결
    ```javascript
    // Anti-Frida 코드...

    // ==========================================

    // Anti-Root 코드...

    // ==========================================

    // Anti-Emulator 코드...
    ```

    ## 로드 순서:
    1. Anti-Frida (가장 먼저 실행되어야 함)
    2. Anti-Root
    3. Anti-Emulator

    ## TODO:
    - 우회 스크립트 우선순위 설정
    - 조건부 우회 (특정 상황에서만 활성화)
    - 우회 성공/실패 로깅
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
