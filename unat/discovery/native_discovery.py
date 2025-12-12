#!/usr/bin/env python3
"""
Native Discovery Module - Native 라이브러리 분석 모듈

Android 앱의 네이티브 라이브러리(.so 파일)를 정적 분석합니다.

## 구현 방식:
1. **ELF 파일 파싱**: pyelftools를 사용하여 ELF 포맷 분석
2. **심볼 테이블 분석**:
   - Exported 함수: STB_GLOBAL/WEAK binding + st_shndx != SHN_UNDEF
   - Imported 함수: st_shndx == SHN_UNDEF인 심볼
3. **보안 기능 탐지**:
   - PIE: e_type == ET_DYN 체크
   - NX: PT_GNU_STACK 세그먼트의 실행 권한 체크
   - Canary: __stack_chk_fail 심볼 존재 확인
   - RELRO: PT_GNU_RELRO 세그먼트 존재 확인
4. **문자열 추출**: .rodata, .data 섹션에서 ASCII 문자열 추출
5. **의존성 분석**: DT_NEEDED 태그에서 공유 라이브러리 의존성 추출

## 개선 예정:
- TODO: C++ 이름 디맹글링 (현재는 간단한 표시만)
- TODO: 디스어셈블리 기능 (capstone 활용)
- TODO: 교차 참조 분석 (함수 호출 관계)
- TODO: 취약한 함수 탐지 (strcpy, gets 등)
- TODO: 암호화 함수 탐지 (AES, RSA 등)
"""

import logging
import re
import struct
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field
from pathlib import Path

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    from elftools.elf.dynamic import DynamicSection
    from elftools.elf.relocation import RelocationSection
    ELFTOOLS_AVAILABLE = True
except ImportError:
    ELFTOOLS_AVAILABLE = False
    logging.warning("pyelftools not available. Native discovery features will be limited.")

try:
    import capstone
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False
    logging.warning("capstone not available. Disassembly features will be limited.")


@dataclass
class NativeFunction:
    """
    Native 함수 정보를 저장하는 데이터 클래스

    Attributes:
        name: 함수 이름 (심볼 테이블에서 추출)
        address: 함수 주소 (st_value)
        size: 함수 크기 (st_size, 바이트 단위)
        type: 심볼 타입 (FUNC=함수, OBJECT=전역변수 등)
        binding: 심볼 바인딩 (GLOBAL=외부 노출, LOCAL=내부 전용, WEAK=약한 심볼)
        demangled_name: C++ 이름 디맹글링 결과 (TODO: 완전한 구현 필요)

    예시:
        NativeFunction(
            name="Java_com_example_MainActivity_nativeMethod",
            address=0x1234,
            size=256,
            type="FUNC",
            binding="GLOBAL"
        )
    """
    name: str
    address: int
    size: int = 0
    type: str = "FUNC"  # FUNC, OBJECT, etc.
    binding: str = "GLOBAL"  # GLOBAL, LOCAL, WEAK
    demangled_name: Optional[str] = None


@dataclass
class NativeLibraryInfo:
    """
    Native 라이브러리 전체 정보를 저장하는 데이터 클래스

    Attributes:
        path: 라이브러리 파일 경로 (APK 내부 경로)
        architecture: CPU 아키텍처 (ARM, ARM64, x86, x86_64 등)
        bit_width: 비트 폭 (32 또는 64)
        endianness: 바이트 순서 (little 또는 big)

        # 보안 기능 플래그
        has_pie: PIE(Position Independent Executable) 활성화 여부
                 - ASLR(Address Space Layout Randomization)을 위해 필요
                 - e_type == ET_DYN으로 확인
        has_nx: NX(No-eXecute) 활성화 여부
                - 스택 영역 코드 실행 방지
                - PT_GNU_STACK 세그먼트의 실행 플래그로 확인
        has_canary: Stack Canary 활성화 여부
                    - 스택 버퍼 오버플로우 탐지
                    - __stack_chk_fail 심볼 존재로 확인
        has_relro: RELRO(Relocation Read-Only) 활성화 여부
                   - GOT(Global Offset Table) 보호
                   - PT_GNU_RELRO 세그먼트 존재로 확인

        # 분석 결과
        exported_functions: Export되는 함수 목록 (외부에서 호출 가능)
        imported_functions: Import하는 함수 목록 (외부 라이브러리 의존)
        strings: 추출된 문자열 목록 (하드코딩된 값, API 키 등)
        sections: ELF 섹션 목록 (.text, .data, .rodata 등)
        dependencies: 의존하는 공유 라이브러리 목록 (libc.so, liblog.so 등)

    보안 플래그 중요도:
        - PIE + RELRO + NX + Canary = 모든 보호 기법 적용 (권장)
        - PIE 미사용 = ASLR 우회 가능
        - NX 미사용 = 코드 인젝션 공격 가능
        - Canary 미사용 = 스택 오버플로우 탐지 불가
        - RELRO 미사용 = GOT Overwrite 공격 가능
    """
    path: str
    architecture: str
    bit_width: int  # 32 or 64
    endianness: str  # little or big
    has_pie: bool = False
    has_nx: bool = False
    has_canary: bool = False
    has_relro: bool = False
    exported_functions: List[NativeFunction] = field(default_factory=list)
    imported_functions: List[str] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    sections: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)


@dataclass
class NativeDiscoveryResult:
    """
    Native Discovery 전체 결과를 저장하는 데이터 클래스

    APK에서 발견된 모든 네이티브 라이브러리의 분석 결과를 집계

    Attributes:
        apk_path: 분석한 APK 파일 경로
        total_libraries: 발견된 라이브러리 총 개수
        total_exported_functions: 모든 라이브러리의 Export 함수 총 개수
        total_imported_functions: 모든 라이브러리의 Import 함수 총 개수
        total_strings: 추출된 문자열 총 개수
        libraries: 각 라이브러리의 상세 정보 목록
    """
    apk_path: str
    total_libraries: int = 0
    total_exported_functions: int = 0
    total_imported_functions: int = 0
    total_strings: int = 0
    libraries: List[NativeLibraryInfo] = field(default_factory=list)


class NativeDiscovery:
    """
    Native Discovery - 네이티브 라이브러리 정적 분석 클래스

    ## 분석 방식:
    pyelftools를 사용한 ELF 파일 파싱 (향후 capstone 디스어셈블리 추가 예정)

    ## 주요 기능:
    1. 심볼 테이블 분석 (Exported/Imported 함수)
    2. 보안 기능 탐지 (PIE, NX, Canary, RELRO)
    3. 문자열 추출 (.rodata, .data 섹션)
    4. 의존성 분석 (DT_NEEDED)
    5. 아키텍처 식별 (ARM, ARM64, x86, x86_64 등)

    ## 개선 필요 사항:
    - TODO: C++ 디맹글링 완전 구현 (c++filt 또는 cxxfilt 라이브러리)
    - TODO: Capstone 디스어셈블리 활용
    - TODO: 함수 간 호출 관계 분석 (Cross-reference)
    - TODO: 취약한 함수 탐지 (strcpy, sprintf, gets 등)
    - TODO: 암호화 함수 자동 탐지 (AES_*, RSA_*, MD5_* 등)
    """

    # Architecture mapping
    # ELF 헤더의 e_machine 필드를 사람이 읽기 쉬운 이름으로 변환
    ARCH_MAP = {
        'EM_ARM': 'ARM',        # 32비트 ARM
        'EM_AARCH64': 'ARM64',  # 64비트 ARM
        'EM_386': 'x86',        # 32비트 x86
        'EM_X86_64': 'x86_64',  # 64비트 x86
        'EM_MIPS': 'MIPS',      # MIPS 아키텍처
    }

    def __init__(self):
        """
        Initialize Native Discovery

        Raises:
            ImportError: If pyelftools is not available
        """
        if not ELFTOOLS_AVAILABLE:
            raise ImportError("pyelftools is required but not installed")

        self.logger = logging.getLogger(__name__)

    def analyze_library(
        self,
        library_path: str,
        extract_strings: bool = True,
        min_string_length: int = 4,
        max_strings: Optional[int] = 1000
    ) -> Optional[NativeLibraryInfo]:
        """
        Analyze a native library file

        Args:
            library_path: Path to the .so file
            extract_strings: Extract printable strings
            min_string_length: Minimum string length to extract
            max_strings: Maximum number of strings to extract

        Returns:
            Optional[NativeLibraryInfo]: Library info or None if failed
        """
        lib_path = Path(library_path)
        if not lib_path.exists():
            self.logger.error(f"Library not found: {library_path}")
            return None

        try:
            with open(library_path, 'rb') as f:
                elf = ELFFile(f)

                # Extract basic info
                lib_info = NativeLibraryInfo(
                    path=str(library_path),
                    architecture=self._get_architecture(elf),
                    bit_width=64 if elf.elfclass == 64 else 32,
                    endianness='little' if elf.little_endian else 'big'
                )

                # Security features
                lib_info.has_pie = self._check_pie(elf)
                lib_info.has_nx = self._check_nx(elf)
                lib_info.has_canary = self._check_canary(elf)
                lib_info.has_relro = self._check_relro(elf)

                # Extract sections
                lib_info.sections = [section.name for section in elf.iter_sections() if section.name]

                # Extract exported functions
                lib_info.exported_functions = self._extract_exported_functions(elf)

                # Extract imported functions
                lib_info.imported_functions = self._extract_imported_functions(elf)

                # Extract dependencies
                lib_info.dependencies = self._extract_dependencies(elf)

                # Extract strings if requested
                if extract_strings:
                    lib_info.strings = self._extract_strings(
                        f,
                        elf,
                        min_length=min_string_length,
                        max_strings=max_strings
                    )

                self.logger.info(
                    f"Analyzed {lib_path.name}: "
                    f"{len(lib_info.exported_functions)} exports, "
                    f"{len(lib_info.imported_functions)} imports, "
                    f"{len(lib_info.strings)} strings"
                )

                return lib_info

        except Exception as e:
            self.logger.error(f"Failed to analyze {library_path}: {e}")
            return None

    def _get_architecture(self, elf: ELFFile) -> str:
        """
        Determine the architecture from ELF header

        Args:
            elf: ELFFile object

        Returns:
            str: Architecture name
        """
        machine = elf.header['e_machine']
        return self.ARCH_MAP.get(machine, machine)

    def _check_pie(self, elf: ELFFile) -> bool:
        """
        PIE (Position Independent Executable) 활성화 여부 확인

        ## 원리:
        - ELF 헤더의 e_type 필드가 ET_DYN이면 PIE 활성화
        - PIE는 ASLR(Address Space Layout Randomization)을 가능하게 함
        - 공격자가 코드/데이터 주소를 예측하기 어렵게 만듦

        ## 보안 의미:
        - PIE 활성화 = 메모리 주소 랜덤화 가능, ROP 공격 방어 강화
        - PIE 비활성화 = 고정 주소로 공격 수월, ASLR 우회 가능
        """
        return elf.header['e_type'] == 'ET_DYN'

    def _check_nx(self, elf: ELFFile) -> bool:
        """
        NX (No-eXecute) 비트 활성화 여부 확인

        ## 원리:
        - PT_GNU_STACK 세그먼트의 p_flags 확인
        - p_flags의 비트 0 (PF_X, 실행 권한)이 0이면 NX 활성화
        - 스택 영역에서 코드 실행을 방지

        ## 보안 의미:
        - NX 활성화 = 스택 버퍼 오버플로우 → 쉘코드 실행 차단
        - NX 비활성화 = 스택에 코드 주입 후 실행 가능 (전통적인 쉘코드 공격)

        ## 구현 세부사항:
        - p_flags & 0x1: 0 = NX 활성화, 1 = 스택 실행 가능
        """
        for segment in elf.iter_segments():
            if segment['p_type'] == 'PT_GNU_STACK':
                # NX enabled if stack is not executable (execute bit = 0)
                return (segment['p_flags'] & 0x1) == 0
        return False  # PT_GNU_STACK 없으면 기본적으로 실행 가능 (오래된 바이너리)

    def _check_canary(self, elf: ELFFile) -> bool:
        """
        Stack Canary 활성화 여부 확인

        ## 원리:
        - 컴파일러가 스택 프레임에 랜덤 값(Canary) 삽입
        - 함수 리턴 전에 Canary 값이 변경되었는지 확인
        - 변경되었으면 __stack_chk_fail 함수 호출하여 프로그램 종료

        ## 탐지 방법:
        - 심볼 테이블에서 __stack_chk_fail 심볼 존재 확인
        - 이 심볼이 있으면 Stack Canary가 컴파일 시 활성화된 것

        ## 보안 의미:
        - Canary 활성화 = 스택 버퍼 오버플로우 탐지, 리턴 주소 덮어쓰기 방지
        - Canary 비활성화 = 버퍼 오버플로우로 리턴 주소 직접 조작 가능

        ## 한계:
        - Canary 값 유출되면 우회 가능
        - 포인터 변수 덮어쓰기는 탐지 불가
        """
        # Look for __stack_chk_fail symbol
        for section in elf.iter_sections():
            if isinstance(section, SymbolTableSection):
                for symbol in section.iter_symbols():
                    if '__stack_chk_fail' in symbol.name:
                        return True
        return False

    def _check_relro(self, elf: ELFFile) -> bool:
        """
        RELRO (Relocation Read-Only) 활성화 여부 확인

        ## 원리:
        - PT_GNU_RELRO 세그먼트가 있으면 RELRO 활성화
        - GOT(Global Offset Table) 영역을 읽기 전용으로 만듦
        - 동적 링킹 후 재배치 완료되면 쓰기 권한 제거

        ## RELRO 종류:
        1. Partial RELRO (기본):
           - GOT는 여전히 쓰기 가능
           - .init_array, .fini_array만 보호
        2. Full RELRO (-Wl,-z,relro,-z,now):
           - 모든 심볼 즉시 바인딩
           - 전체 GOT를 읽기 전용으로 설정

        ## 보안 의미:
        - RELRO 활성화 = GOT Overwrite 공격 방어
        - RELRO 비활성화 = 공격자가 GOT 엔트리 조작하여 임의 함수 실행 가능

        ## 한계:
        - Partial RELRO는 .got.plt는 여전히 쓰기 가능
        - Full RELRO 권장하지만 프로그램 시작 시간 증가

        ## TODO:
        - Partial vs Full RELRO 구분 필요
        - DT_BIND_NOW 플래그 확인으로 Full RELRO 판별
        """
        for segment in elf.iter_segments():
            if segment['p_type'] == 'PT_GNU_RELRO':
                return True
        return False

    def _extract_exported_functions(self, elf: ELFFile) -> List[NativeFunction]:
        """
        심볼 테이블에서 Exported 함수 추출

        ## Exported 함수란?
        - 외부에서 호출 가능한 함수 (다른 라이브러리나 Java에서 접근)
        - JNI 함수들이 여기에 포함됨 (Java_com_example_...)

        ## 추출 조건:
        1. **Binding**: STB_GLOBAL 또는 STB_WEAK
           - STB_GLOBAL: 외부에 노출되는 일반 심볼
           - STB_WEAK: 약한 심볼 (다른 라이브러리에서 오버라이드 가능)
           - STB_LOCAL은 제외 (라이브러리 내부 전용)

        2. **Type**: STT_FUNC 또는 STT_OBJECT
           - STT_FUNC: 함수
           - STT_OBJECT: 전역 변수

        3. **Definition**: st_shndx != SHN_UNDEF
           - SHN_UNDEF면 다른 라이브러리에서 import하는 심볼
           - Defined 심볼만 export로 간주

        ## 보안 분석 활용:
        - JNI 함수 식별: Java_로 시작하는 함수
        - 민감한 함수 발견: decrypt, verify, check 등
        - 난독화 여부: 함수 이름이 무의미한 문자인지 확인

        ## TODO:
        - C++ 함수 디맹글링 완전 구현
        - JNI 함수 자동 분류
        - 위험 함수 자동 태깅 (system, exec, popen 등)
        """
        functions = []

        for section in elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue

            for symbol in section.iter_symbols():
                # Only export global/weak functions
                if symbol['st_info']['bind'] not in ('STB_GLOBAL', 'STB_WEAK'):
                    continue

                # Only functions and objects
                symbol_type = symbol['st_info']['type']
                if symbol_type not in ('STT_FUNC', 'STT_OBJECT'):
                    continue

                # Must have a name and be defined (not imported)
                if not symbol.name or symbol['st_shndx'] == 'SHN_UNDEF':
                    continue

                func = NativeFunction(
                    name=symbol.name,
                    address=symbol['st_value'],
                    size=symbol['st_size'],
                    type='FUNC' if symbol_type == 'STT_FUNC' else 'OBJECT',
                    binding=symbol['st_info']['bind'][4:],  # Remove 'STB_' prefix
                    demangled_name=self._demangle_name(symbol.name)
                )
                functions.append(func)

        return sorted(functions, key=lambda f: f.address)

    def _extract_imported_functions(self, elf: ELFFile) -> List[str]:
        """
        심볼 테이블에서 Imported 함수 추출

        ## Imported 함수란?
        - 다른 라이브러리에서 가져오는 함수 (외부 의존성)
        - 예: libc.so의 malloc, pthread_create 등

        ## 추출 조건:
        - st_shndx == SHN_UNDEF: 현재 라이브러리에 정의되지 않음
        - st_info['type'] == STT_FUNC: 함수 타입

        ## 보안 분석 활용:
        - 위험 함수 사용 탐지: system, exec, dlopen 등
        - 암호화 라이브러리 사용 확인: libcrypto.so 함수들
        - 네트워크 함수 사용: socket, connect, send 등
        - 안티 디버깅 함수: ptrace, prctl 등

        ## TODO:
        - 위험 함수 자동 분류 및 경고
        - 함수별 위험도 점수화
        - 의존성 그래프 생성
        """
        imports = set()

        for section in elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue

            for symbol in section.iter_symbols():
                # Look for undefined symbols (imports)
                if symbol['st_shndx'] == 'SHN_UNDEF' and symbol.name:
                    # Only include functions, not objects
                    if symbol['st_info']['type'] == 'STT_FUNC':
                        imports.add(symbol.name)

        return sorted(list(imports))

    def _extract_dependencies(self, elf: ELFFile) -> List[str]:
        """
        공유 라이브러리 의존성 추출

        ## 원리:
        - DynamicSection에서 DT_NEEDED 태그를 찾음
        - DT_NEEDED는 이 라이브러리가 로드 시 필요로 하는 다른 라이브러리 목록

        ## 의존성 예시:
        - libc.so: C 표준 라이브러리 (거의 모든 네이티브 코드가 의존)
        - liblog.so: Android 로깅 라이브러리
        - libcrypto.so: OpenSSL 암호화 라이브러리
        - libcurl.so: HTTP 통신 라이브러리

        ## 보안 분석 활용:
        - 암호화 라이브러리 사용 확인 (libssl, libcrypto)
        - 네트워크 라이브러리 사용 (libcurl, libwebsockets)
        - 의심스러운 라이브러리 탐지 (비표준 라이브러리)
        - 난독화/패킹 도구 흔적 (UPX, Themida 등)

        ## TODO:
        - 재귀적 의존성 분석 (의존성의 의존성)
        - 라이브러리 버전 정보 추출
        - 취약한 라이브러리 버전 경고
        """
        dependencies = []

        for section in elf.iter_sections():
            if not isinstance(section, DynamicSection):
                continue

            for tag in section.iter_tags():
                if tag.entry.d_tag == 'DT_NEEDED':
                    dependencies.append(tag.needed)

        return dependencies

    def _extract_strings(
        self,
        file_handle,
        elf: ELFFile,
        min_length: int = 4,
        max_strings: Optional[int] = 1000
    ) -> List[str]:
        """
        라이브러리에서 출력 가능한 문자열 추출

        ## 추출 대상 섹션:
        - .rodata: 읽기 전용 데이터 (문자열 리터럴, 상수)
        - .data: 초기화된 전역 변수
        - .dynstr: 동적 심볼 문자열
        - .strtab: 문자열 테이블

        ## 추출 알고리즘:
        1. 각 섹션을 바이트 단위로 순회
        2. ASCII 출력 가능 범위(32-126)인 바이트를 수집
        3. 출력 불가능 바이트를 만나면 문자열 종료
        4. 최소 길이(min_length) 이상인 문자열만 저장
        5. UTF-8 디코딩 시도, 실패하면 무시

        ## 보안 분석 활용:
        - 하드코딩된 API 키/비밀번호 탐지
        - URL/도메인 정보 추출 (C&C 서버 등)
        - 디버그 메시지/에러 메시지로 기능 추정
        - 난독화된 문자열 패턴 발견
        - 암호화 알고리즘 힌트 ("AES", "RSA" 등)

        ## 성능 최적화:
        - max_strings로 메모리 사용량 제한
        - set()으로 중복 제거
        - 공백만 있는 문자열 필터링

        ## TODO:
        - Base64 인코딩된 문자열 디코딩
        - XOR 인코딩 자동 탐지 및 디코딩
        - Unicode 문자열 지원 (UTF-16, UTF-32)
        - 정규식 패턴 매칭 (URL, 이메일, IP 주소 등)
        - 엔트로피 분석으로 암호화된 문자열 탐지
        """
        strings = set()

        # Common sections to search for strings
        string_sections = ['.rodata', '.data', '.dynstr', '.strtab']

        for section in elf.iter_sections():
            if section.name not in string_sections:
                continue

            data = section.data()
            current_string = b''

            for byte in data:
                # Printable ASCII range (스페이스(32) ~ 틸드(126))
                if 32 <= byte <= 126:
                    current_string += bytes([byte])
                else:
                    if len(current_string) >= min_length:
                        try:
                            decoded = current_string.decode('utf-8', errors='ignore')
                            if decoded and not decoded.isspace():
                                strings.add(decoded)
                        except:
                            pass
                    current_string = b''

            # Handle last string (섹션 끝에 null 종료자 없는 문자열 처리)
            if len(current_string) >= min_length:
                try:
                    decoded = current_string.decode('utf-8', errors='ignore')
                    if decoded and not decoded.isspace():
                        strings.add(decoded)
                except:
                    pass

        # Limit number of strings (메모리 사용량 제한)
        result = sorted(list(strings))
        if max_strings:
            result = result[:max_strings]

        return result

    def _demangle_name(self, name: str) -> Optional[str]:
        """
        C++ 심볼 이름 디맹글링 시도

        ## C++ 이름 맹글링이란?
        - C++는 함수 오버로딩, 네임스페이스, 템플릿 등을 지원
        - 링커가 구분하기 위해 함수 이름을 인코딩 (맹글링)
        - 예: `_ZN7MyClass10myFunctionEi` → `MyClass::myFunction(int)`

        ## 현재 구현:
        - 간단한 탐지만 수행 (_Z로 시작하면 C++ 맹글 심볼)
        - 실제 디맹글링은 미구현 (표시만 함)

        ## TODO - 완전한 디맹글링 구현:
        방법 1: subprocess로 c++filt 호출
        ```python
        import subprocess
        result = subprocess.run(['c++filt', name], capture_output=True, text=True)
        return result.stdout.strip()
        ```

        방법 2: cxxfilt 라이브러리 사용
        ```python
        import cxxfilt
        return cxxfilt.demangle(name)
        ```

        방법 3: llvm-cxxfilt 사용 (더 정확)
        ```python
        result = subprocess.run(['llvm-cxxfilt', name], ...)
        ```

        ## 맹글링 규칙:
        - Itanium C++ ABI (GCC, Clang): _Z로 시작
        - MSVC: ?로 시작 (Windows)
        - 예시:
          - `_Z3fooi` → `foo(int)`
          - `_ZN3Bar3bazEv` → `Bar::baz()`
          - `_ZNSt6vectorIiE4pushEi` → `std::vector<int>::push(int)`

        ## 보안 분석 활용:
        - C++ 클래스/메서드 구조 파악
        - 템플릿 인스턴스화 확인
        - STL 사용 패턴 분석
        """
        # Simple C++ name demangling
        # For full demangling, we'd need c++filt or a dedicated library
        if name.startswith('_Z'):
            # This is a mangled C++ name (Itanium C++ ABI)
            # We'll just return a note for now
            return f"<C++ mangled: {name[:20]}...>" if len(name) > 20 else f"<C++ mangled: {name}>"
        elif name.startswith('?'):
            # MSVC C++ mangling (Windows)
            return f"<MSVC mangled: {name[:20]}...>" if len(name) > 20 else f"<MSVC mangled: {name}>"
        return None  # Not a mangled name

    def discover_from_apk(
        self,
        apk_path: str,
        extract_strings: bool = True,
        min_string_length: int = 4,
        max_strings_per_lib: Optional[int] = 1000
    ) -> Optional[NativeDiscoveryResult]:
        """
        Discover all native libraries in an APK

        Args:
            apk_path: Path to the APK file
            extract_strings: Extract strings from libraries
            min_string_length: Minimum string length
            max_strings_per_lib: Maximum strings per library

        Returns:
            Optional[NativeDiscoveryResult]: Discovery results
        """
        from zipfile import ZipFile

        apk_file = Path(apk_path)
        if not apk_file.exists():
            self.logger.error(f"APK not found: {apk_path}")
            return None

        result = NativeDiscoveryResult(apk_path=str(apk_path))

        try:
            with ZipFile(apk_path, 'r') as apk:
                # Find all .so files
                so_files = [name for name in apk.namelist() if name.endswith('.so')]

                if not so_files:
                    self.logger.warning("No native libraries found in APK")
                    return result

                self.logger.info(f"Found {len(so_files)} native libraries")

                # Extract and analyze each library
                import tempfile
                with tempfile.TemporaryDirectory() as temp_dir:
                    for so_file in so_files:
                        # Extract to temp directory
                        temp_path = Path(temp_dir) / Path(so_file).name
                        with apk.open(so_file) as src, open(temp_path, 'wb') as dst:
                            dst.write(src.read())

                        # Analyze library
                        lib_info = self.analyze_library(
                            str(temp_path),
                            extract_strings=extract_strings,
                            min_string_length=min_string_length,
                            max_strings=max_strings_per_lib
                        )

                        if lib_info:
                            # Update path to show original location in APK
                            lib_info.path = so_file
                            result.libraries.append(lib_info)

                # Calculate totals
                result.total_libraries = len(result.libraries)
                result.total_exported_functions = sum(
                    len(lib.exported_functions) for lib in result.libraries
                )
                result.total_imported_functions = sum(
                    len(lib.imported_functions) for lib in result.libraries
                )
                result.total_strings = sum(
                    len(lib.strings) for lib in result.libraries
                )

                self.logger.info(
                    f"Discovery complete: {result.total_libraries} libraries, "
                    f"{result.total_exported_functions} exports, "
                    f"{result.total_imported_functions} imports"
                )

                return result

        except Exception as e:
            self.logger.error(f"Failed to discover native libraries: {e}")
            return None


def discover_native_libraries(
    apk_path: str,
    extract_strings: bool = True,
    min_string_length: int = 4
) -> Optional[NativeDiscoveryResult]:
    """
    Convenience function to discover native libraries

    Args:
        apk_path: Path to the APK file
        extract_strings: Extract strings from libraries
        min_string_length: Minimum string length

    Returns:
        Optional[NativeDiscoveryResult]: Discovery results or None if failed
    """
    discovery = NativeDiscovery()

    try:
        result = discovery.discover_from_apk(
            apk_path=apk_path,
            extract_strings=extract_strings,
            min_string_length=min_string_length
        )
        return result

    except Exception as e:
        logging.error(f"Native discovery failed: {e}")
        return None
