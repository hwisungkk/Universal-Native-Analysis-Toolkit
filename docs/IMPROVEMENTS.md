# UNAT 개선 필요 사항 및 구현 설명

> 작성일: 2024-12-12
> 현재까지 구현된 분석 및 후킹 기능에 대한 상세 설명 및 개선 필요 사항

---

## 📋 목차

1. [Java Discovery](#1-java-discovery)
2. [Native Discovery](#2-native-discovery)
3. [JNI Discovery](#3-jni-discovery)
4. [Hooking Engine](#4-hooking-engine)
5. [Evasion Module](#5-evasion-module)
6. [전체 아키텍처 개선 사항](#6-전체-아키텍처-개선-사항)

---

## 1. Java Discovery

### 📖 현재 구현 방식

#### 동작 원리
1. **Frida 프로세스 Attach**
   - `device.spawn()` 또는 `device.attach()` 사용
   - 타겟 앱 프로세스에 연결

2. **JavaScript 스크립트 주입**
   - `Java.enumerateLoadedClasses()` API 사용
   - 로드된 모든 Java 클래스 목록 수집

3. **클래스 정보 수집**
   - 각 클래스의 `getDeclaredMethods()` 호출
   - 메서드 시그니처 추출

4. **난독화 탐지**
   - 정규식 패턴 매칭
   - 패턴 예시:
     - `^[a-z]$` - 단일 문자 (ProGuard 기본)
     - `^[a-z0-9]{1,3}$` - 짧은 이름
     - `[O0][O0]` - 혼동 패턴 (O0O, 00O)

#### 파일 위치
- `unat/discovery/java_discovery.py`
- `frida_scripts/templates/enumerate_classes.js`
- `frida_scripts/templates/enumerate_methods.js`

### ⚠️ 개선 필요 사항

#### 1. 성능 개선
```python
# 현재: 고정된 대기 시간
time.sleep(2)  # FIXME: 클래스 수에 따라 부족할 수 있음

# 개선안: 완료 시그널 기반 대기
# JavaScript에서 완료 시그널 전송하고 Python에서 대기
```

**문제점:**
- 클래스가 많은 앱에서는 2초로 부족
- 클래스가 적은 앱에서는 불필요한 대기

**해결 방안:**
- Event 기반 동기화 사용
- 진행률 피드백 추가

#### 2. 메서드 열거 병렬 처리
```python
# 현재: 순차적 처리
for class_info in classes:
    methods = self.enumerate_methods(class_info.name)

# 개선안: 병렬 처리
from concurrent.futures import ThreadPoolExecutor
with ThreadPoolExecutor(max_workers=10) as executor:
    futures = [executor.submit(self.enumerate_methods, c.name)
               for c in classes]
```

**장점:**
- 수백~수천 개 클래스 처리 시 10배 이상 속도 향상

#### 3. 난독화 탐지 개선
```python
# 현재: 정규식 패턴만 사용
self.obfuscation_patterns = [
    r'^[a-z]$',
    r'^[a-z0-9]{1,3}$',
]

# 개선안 1: Entropy 계산
import math
def calc_entropy(s):
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    entropy = -sum(p * math.log2(p) for p in prob)
    return entropy
# 낮은 entropy = 난독화 가능성 높음 (예: 'aaa', 'bbb')

# 개선안 2: 영어 사전 기반
import enchant
d = enchant.Dict("en_US")
if not d.check(class_name):
    # 영어 단어가 아니면 난독화 가능성 높음

# 개선안 3: 머신러닝 분류기
# 학습 데이터: 난독화된 클래스 vs 정상 클래스
# 특징: 길이, entropy, 특수문자 비율, 숫자 비율 등
```

#### 4. 미구현 기능

**필드 정보 추출:**
```python
# TODO: 필드 정보 추출 미구현
fields: List[str] = field(default_factory=list)

# 구현 방안:
# JavaScript에서 class.getDeclaredFields() 호출
var fields = targetClass.class.getDeclaredFields();
fields.forEach(function(field) {
    send({
        name: field.getName(),
        type: field.getType().getName(),
        modifiers: field.getModifiers()
    });
});
```

**클래스 상속 관계:**
```python
# TODO: 상속 관계 추적
# 구현 방안:
var superClass = targetClass.class.getSuperclass();
var interfaces = targetClass.class.getInterfaces();
```

**어노테이션 정보:**
```python
# TODO: 어노테이션 추출
# 구현 방안:
var annotations = targetClass.class.getAnnotations();
```

#### 5. 에러 처리 개선
```python
# 현재: 단순 로깅만
except Exception as e:
    self.logger.warning(f"Failed to enumerate methods: {e}")

# 개선안: 재시도 로직
from tenacity import retry, stop_after_attempt, wait_fixed

@retry(stop=stop_after_attempt(3), wait=wait_fixed(1))
def enumerate_methods_with_retry(self, class_name):
    return self.enumerate_methods(class_name)
```

---

## 2. Native Discovery

### 📖 현재 구현 방식

#### 동작 원리
1. **APK에서 .so 파일 추출**
   - `zipfile`로 APK 열기
   - `lib/` 디렉토리에서 `.so` 파일 찾기

2. **ELF 파일 파싱 (pyelftools 사용)**
   - ELF 헤더 분석: 아키텍처, 엔디안, 비트 폭
   - 섹션 파싱: .text, .data, .rodata 등

3. **심볼 테이블 분석**
   - Exported 함수: `STB_GLOBAL` + `STT_FUNC` + `st_shndx != SHN_UNDEF`
   - Imported 함수: `st_shndx == SHN_UNDEF`

4. **보안 기능 체크**
   - PIE: `e_type == ET_DYN`
   - NX: `PT_GNU_STACK`의 `p_flags`
   - Canary: `__stack_chk_fail` 심볼 존재 여부
   - RELRO: `PT_GNU_RELRO` 세그먼트

5. **문자열 추출**
   - `.rodata`, `.data` 섹션 스캔
   - 연속된 출력 가능 ASCII 문자 추출

#### 파일 위치
- `unat/discovery/native_discovery.py`

### ⚠️ 개선 필요 사항

#### 1. C++ Name Demangling
```python
# 현재: 단순 문자열 처리만
def _demangle_name(self, name: str) -> Optional[str]:
    if name.startswith('_Z'):
        return f"<C++ mangled: {name}>"
    return None

# 개선안: c++filt 또는 라이브러리 사용
import subprocess
def demangle_cpp_name(mangled):
    try:
        result = subprocess.run(
            ['c++filt', mangled],
            capture_output=True,
            text=True
        )
        return result.stdout.strip()
    except:
        return mangled

# 또는 Python 라이브러리 사용
# pip install pyc++filt
from cxxfilt import demangle
demangled = demangle(mangled_name)
```

#### 2. 디스어셈블리 기능
```python
# TODO: Capstone 사용하여 함수 디스어셈블
import capstone

def disassemble_function(self, address, size):
    # .text 섹션에서 바이너리 읽기
    code = self.read_bytes(address, size)

    # 아키텍처에 맞는 디스어셈블러 선택
    if self.arch == 'ARM':
        md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    elif self.arch == 'ARM64':
        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)

    # 디스어셈블
    for insn in md.disasm(code, address):
        print(f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
```

#### 3. 문자열 추출 개선
```python
# 현재: 단순 ASCII만 추출
if 32 <= byte <= 126:
    current_string += bytes([byte])

# 개선안 1: UTF-8 문자열 지원
# 한글, 중국어 등 멀티바이트 문자 처리

# 개선안 2: 문자열 분류
def classify_strings(self, strings):
    classified = {
        'urls': [],      # http://, https://
        'paths': [],     # /data/, /system/
        'api_keys': [],  # 특정 패턴의 키
        'crypto': [],    # AES, RSA 등 키워드
        'suspicious': [] # eval, exec 등
    }

    for s in strings:
        if s.startswith('http'):
            classified['urls'].append(s)
        elif '/' in s and len(s) > 5:
            classified['paths'].append(s)
        # ... 패턴 매칭

    return classified
```

#### 4. 크로스 레퍼런스 분석
```python
# TODO: 함수 간 호출 관계 분석
def analyze_xrefs(self, function_address):
    """
    특정 함수를 호출하는 위치 찾기

    구현 방안:
    1. .text 섹션 디스어셈블
    2. BL, BLX (ARM) 또는 CALL (x86) 명령어 찾기
    3. 타겟 주소 계산
    4. 호출 그래프 생성
    """
    pass
```

#### 5. PLT/GOT 분석
```python
# TODO: PLT (Procedure Linkage Table) 분석
def analyze_plt(self):
    """
    동적 링킹 정보 상세 분석

    - PLT 엔트리 파싱
    - GOT (Global Offset Table) 주소
    - Lazy binding 여부
    """
    plt_section = self.elf.get_section_by_name('.plt')
    got_section = self.elf.get_section_by_name('.got')
```

---

## 3. JNI Discovery

### 📖 현재 구현 방식

#### 동작 원리
1. **RegisterNatives 가로채기**
   - Frida로 `RegisterNatives` 함수 후킹
   - JNINativeMethod 구조체 파싱:
     ```c
     typedef struct {
         const char* name;      // 메서드 이름
         const char* signature; // 시그니처
         void* fnPtr;           // 네이티브 함수 포인터
     } JNINativeMethod;
     ```

2. **Native 메서드 열거**
   - `Java.enumerateLoadedClasses()` 실행
   - 각 클래스의 `getDeclaredMethods()` 호출
   - Modifier 체크: `modifiers & 0x100` (NATIVE 플래그)

#### 파일 위치
- `unat/discovery/jni_discovery.py`
- `frida_scripts/templates/jni_discovery.js`

### ⚠️ 개선 필요 사항

#### 1. JNI 호출 추적
```javascript
// TODO: JNI 함수 호출 추적
// 구현 방안:
Interceptor.attach(Module.findExportByName(null, 'JNI_OnLoad'), {
    onEnter: function(args) {
        console.log('[+] JNI_OnLoad called');
        // JavaVM* 저장
        this.vm = args[0];
    }
});

// JNIEnv 함수들 후킹
var jniEnvMethods = [
    'FindClass',
    'GetMethodID',
    'CallObjectMethod',
    'NewStringUTF'
];
```

#### 2. JNINativeMethod 구조체 파싱 개선
```python
# 현재: 고정 크기 가정
offset = Process.pointerSize === 8 ? i * 24 : i * 12

# 문제: 플랫폼마다 다를 수 있음

# 개선안: 동적 크기 계산
import ctypes
class JNINativeMethod(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char_p),
        ("signature", ctypes.c_char_p),
        ("fnPtr", ctypes.c_void_p)
    ]
```

#### 3. JNI 함수 시그니처 파싱
```python
# TODO: JNI 시그니처를 사람이 읽기 쉬운 형태로 변환
def parse_jni_signature(sig: str) -> str:
    """
    (ILjava/lang/String;)V → void methodName(int, String)

    매핑 테이블:
    V -> void
    Z -> boolean
    B -> byte
    C -> char
    S -> short
    I -> int
    J -> long
    F -> float
    D -> double
    Lxxx; -> xxx (객체)
    [X -> X[] (배열)
    """
    pass
```

#### 4. JNI 메모리 누수 탐지
```javascript
// TODO: NewStringUTF, NewGlobalRef 등의 짝이 맞는지 확인
var allocations = {};

Interceptor.attach(Module.findExportByName(null, 'NewStringUTF'), {
    onLeave: function(retval) {
        allocations[retval] = {
            type: 'string',
            backtrace: Thread.backtrace()
        };
    }
});

Interceptor.attach(Module.findExportByName(null, 'DeleteLocalRef'), {
    onEnter: function(args) {
        delete allocations[args[1]];
    }
});

// 주기적으로 allocations 체크하여 누수 탐지
```

---

## 4. Hooking Engine

### 📖 현재 구현 방식

#### 동작 원리
1. **Frida Engine 초기화**
   - 프로세스 attach
   - 스크립트 로드 및 관리

2. **Java Method Hooking**
   ```javascript
   Java.use("com.example.Class")[methodName]
       .overloads[idx].implementation = function() {
           // 인자 로깅
           // 원본 메서드 호출
           // 반환값 로깅
       };
   ```

3. **Native Function Hooking**
   ```javascript
   Interceptor.attach(address, {
       onEnter: function(args) {
           // 인자 캡처
           // 레지스터 상태 로깅
       },
       onLeave: function(retval) {
           // 반환값 로깅
       }
   });
   ```

4. **메시지 핸들링**
   - JavaScript → Python 메시지 전송
   - 커스텀 핸들러 등록 가능

#### 파일 위치
- `unat/hooking/frida_engine.py`
- `unat/hooking/hook_templates.py`
- `frida_scripts/templates/java_hook.js`
- `frida_scripts/templates/native_hook.js`

### ⚠️ 개선 필요 사항

#### 1. 인자 값 스마트 파싱
```javascript
// 현재: 단순 toString()
argStrings.push(args[i].toString());

// 개선안: 타입별 처리
function smartParse(arg) {
    if (arg === null) return 'null';
    if (arg === undefined) return 'undefined';

    // Java 객체인 경우
    if (Java.available) {
        try {
            var clazz = Java.cast(arg, Java.use("java.lang.Object")).getClass();
            var className = clazz.getName();

            // 타입별 특수 처리
            if (className === 'java.lang.String') {
                return '"' + arg.toString() + '"';
            } else if (className === '[B') {
                // byte[] → hex dump
                return hexdump(arg);
            } else if (className.startsWith('[')) {
                // 배열 → 요소들 출력
                return arrayToString(arg);
            }
        } catch (e) {}
    }

    return arg.toString();
}
```

#### 2. 조건부 후킹
```python
# TODO: 특정 조건에서만 후킹 활성화
config = HookConfig(
    class_name="com.example.Crypto",
    method_name="encrypt",
    # 조건 추가
    condition="arguments[0].length > 10"  # 첫 번째 인자 길이가 10 이상일 때만
)

# JavaScript 템플릿에 조건 주입
if (CONDITION) {
    // 로깅 수행
}
```

#### 3. 반환값 변조
```python
# TODO: 반환값 변경 기능
config = HookConfig(
    class_name="com.example.License",
    method_name="isValid",
    modify_return=True,
    return_value="true"  # 항상 true 반환
)

# JavaScript:
clazz.isValid.implementation = function() {
    var result = this.isValid.call(this);
    console.log('Original result:', result);
    return RETURN_VALUE;  // 강제로 변경
};
```

#### 4. 호출 빈도 제한
```python
# TODO: 같은 함수가 너무 자주 호출되면 로깅 생략
var lastLog = 0;
var minInterval = 1000; // 1초

onEnter: function(args) {
    var now = Date.now();
    if (now - lastLog < minInterval) {
        return; // 로깅 건너뛰기
    }
    lastLog = now;
    // 로깅 수행
}
```

#### 5. 스택 트레이스 필터링
```javascript
// 현재: 전체 스택 출력
var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE);

// 개선안: 유용한 부분만 필터링
var filtered = backtrace.filter(function(addr) {
    var symbol = DebugSymbol.fromAddress(addr);
    // 시스템 라이브러리 제외
    if (symbol.moduleName.startsWith('libc.so')) return false;
    if (symbol.moduleName.startsWith('libart.so')) return false;
    return true;
});
```

---

## 5. Evasion Module

### 📖 현재 구현 방식

#### Anti-Frida Bypass
1. **Named Pipe 탐지 우회**
   - `File.exists()` 후킹
   - `frida-*` 경로 차단

2. **포트 스캔 우회**
   - `connect()` 후킹
   - 포트 27042, 27043 차단

3. **문자열 검사 우회**
   - `strstr()`, `strcmp()` 후킹
   - "frida" 문자열 검사 무효화

#### Anti-Root Bypass
1. **su 바이너리 체크 우회**
   - 30개 이상의 경로 차단
   - `File.exists()`, `fopen()`, `access()` 후킹

2. **RootBeer 라이브러리 우회**
   - `isRooted()` 메서드 후킹
   - 항상 false 반환

3. **Build.TAGS 조작**
   - `test-keys` → `release-keys`

#### Anti-Emulator Bypass
1. **Build 속성 스푸핑**
   - Samsung Galaxy S21로 위장
   - MANUFACTURER, MODEL, BRAND 등 변경

2. **IMEI/전화번호 스푸핑**
   - 랜덤 IMEI 생성
   - `getDeviceId()`, `getLine1Number()` 후킹

3. **센서 스푸핑**
   - `SensorManager.getSensorList()` 후킹

#### 파일 위치
- `unat/evasion/evasion_manager.py`
- `frida_scripts/evasion/anti_frida_bypass.js`
- `frida_scripts/evasion/anti_root_bypass.js`
- `frida_scripts/evasion/anti_emulator_bypass.js`

### ⚠️ 개선 필요 사항

#### 1. SSL Pinning Bypass 추가
```javascript
// TODO: SSL 인증서 검증 우회
// okhttp3
Java.use("okhttp3.CertificatePinner")
    .check$okhttp.overload('java.lang.String', 'java.util.List')
    .implementation = function() {
        console.log('[+] SSL Pinning bypassed (OkHttp)');
        return;
    };

// TrustManager
Java.use("javax.net.ssl.X509TrustManager")
    .checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String')
    .implementation = function() {
        console.log('[+] SSL Pinning bypassed (TrustManager)');
        return;
    };
```

#### 2. Anti-Debugging Bypass
```javascript
// TODO: 디버깅 탐지 우회
// ptrace
Interceptor.attach(Module.findExportByName(null, 'ptrace'), {
    onEnter: function(args) {
        if (args[0].toInt32() === 0) { // PTRACE_TRACEME
            console.log('[+] Blocked ptrace(PTRACE_TRACEME)');
            args[0] = ptr(-1);
        }
    }
});

// TracerPid 체크
Interceptor.attach(Module.findExportByName(null, 'fopen'), {
    onEnter: function(args) {
        var path = Memory.readUtf8String(args[0]);
        if (path === '/proc/self/status') {
            // TracerPid를 0으로 변조
        }
    }
});
```

#### 3. Hooking Detection Bypass
```javascript
// TODO: 후킹 탐지 우회
// Substrate/Xposed 탐지
Java.use("java.lang.Runtime").loadLibrary.implementation = function(lib) {
    if (lib.indexOf('substrate') !== -1 || lib.indexOf('xposed') !== -1) {
        console.log('[+] Blocked loadLibrary:' + lib);
        throw new Error('Library not found');
    }
    return this.loadLibrary(lib);
};
```

#### 4. Memory Scanning Bypass
```javascript
// TODO: 메모리 스캔 우회
// /proc/self/maps 읽기 차단
var maps = Memory.allocUtf8String(generateFakeMaps());

Interceptor.attach(Module.findExportByName(null, 'read'), {
    onLeave: function(retval) {
        // /proc/self/maps인 경우 가짜 데이터 반환
    }
});
```

#### 5. Integrity Check Bypass
```javascript
// TODO: 무결성 검사 우회
// DEX/APK 체크섬 검증
Java.use("java.util.zip.ZipFile").getEntry.implementation = function(name) {
    var entry = this.getEntry.call(this, name);
    if (name === 'classes.dex') {
        // CRC 변조
    }
    return entry;
};
```

---

## 6. 전체 아키텍처 개선 사항

### 1. 설정 파일 시스템
```yaml
# TODO: config/profiles.yaml
profiles:
  aggressive:
    evasion:
      anti_frida: true
      anti_root: true
      anti_emulator: true
      ssl_pinning: true
    hooking:
      log_args: true
      log_return: true
      backtrace: true

  stealth:
    evasion:
      anti_frida: true
      anti_root: false
      anti_emulator: false
    hooking:
      log_args: false
      log_return: true
      backtrace: false
```

### 2. 플러그인 시스템
```python
# TODO: 플러그인 아키텍처
class DiscoveryPlugin:
    def discover(self, session):
        pass

class CustomDiscovery(DiscoveryPlugin):
    def discover(self, session):
        # 커스텀 탐색 로직
        pass

# 플러그인 등록
discovery.register_plugin(CustomDiscovery())
```

### 3. 결과 캐싱
```python
# TODO: Discovery 결과 캐싱
import hashlib
import pickle

def get_cache_key(apk_path):
    with open(apk_path, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()

def cached_discovery(apk_path):
    key = get_cache_key(apk_path)
    cache_file = f'.cache/{key}.pkl'

    if os.path.exists(cache_file):
        with open(cache_file, 'rb') as f:
            return pickle.load(f)

    result = discover(apk_path)

    with open(cache_file, 'wb') as f:
        pickle.dump(result, f)

    return result
```

### 4. 진행률 표시
```python
# TODO: 진행률 표시
from tqdm import tqdm

for class_info in tqdm(classes, desc="Enumerating methods"):
    methods = enumerate_methods(class_info.name)
```

### 5. 로깅 개선
```python
# TODO: 구조화된 로깅
import structlog

logger = structlog.get_logger()
logger.info(
    "method_called",
    class_name="com.example.Crypto",
    method_name="encrypt",
    args_count=2,
    return_type="byte[]"
)

# JSON 형식으로 출력 가능
```

### 6. 테스트 코드
```python
# TODO: 유닛 테스트 추가
# tests/test_java_discovery.py

import pytest
from unat.discovery.java_discovery import JavaDiscovery

class TestJavaDiscovery:
    def test_obfuscation_detection(self):
        discovery = JavaDiscovery(None, "com.test")

        assert discovery._is_obfuscated("a.b.c.D") == True
        assert discovery._is_obfuscated("com.example.MyClass") == False

    def test_enumerate_classes(self, mock_frida_session):
        discovery = JavaDiscovery(mock_frida_session, "com.test")
        classes = discovery.enumerate_classes()

        assert len(classes) > 0
        assert all(c.package.startswith("com.test") for c in classes)
```

### 7. 문서화
```python
# TODO: Sphinx 문서 자동 생성
# docs/conf.py

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.napoleon',  # Google/NumPy 스타일 docstring
    'sphinx_rtd_theme',     # Read the Docs 테마
]

# API 문서 자동 생성
# make html
```

### 8. CI/CD 파이프라인
```yaml
# TODO: .github/workflows/test.yml

name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Set up Python
        uses: actions/setup-python@v2
      - name: Install dependencies
        run: pip install -r requirements.txt
      - name: Run tests
        run: pytest tests/ -v
      - name: Code coverage
        run: pytest --cov=unat tests/
```

---

## 📚 참고 자료

### Frida 문서
- https://frida.re/docs/
- https://frida.re/docs/javascript-api/

### ELF 파일 형식
- https://refspecs.linuxbase.org/elf/elf.pdf

### JNI 스펙
- https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/jniTOC.html

### Android 보안
- https://source.android.com/security

---

## 📝 요약

이 문서는 UNAT의 현재 구현 상태와 개선 필요 사항을 정리합니다.

**주요 개선 방향:**
1. 성능 최적화 (병렬 처리, 캐싱)
2. 기능 확장 (디스어셈블리, 크로스 레퍼런스)
3. 탐지 정확도 향상 (머신러닝, entropy)
4. 사용성 개선 (진행률, 설정 파일)
5. 안정성 강화 (테스트, 에러 처리)

모든 개선 사항은 우선순위에 따라 단계적으로 구현할 예정입니다.
