# UNAT 작업 목록 (TODO)

> 마지막 업데이트: 2024-12-12 (Phase 3 Hooking 엔진 완료)

---

## 📌 [긴급] Phase 2 - Discovery 모듈

### Java Discovery
- [x] **unat/discovery/java_discovery.py** ✅
  - [x] Java 클래스 스캔 기능
  - [x] 메서드 목록 추출
  - [x] 생성자 정보 추출
  - [x] 난독화 패턴 인식
  - [x] CLI 통합 (`unat discover`)
  - [ ] 필드 정보 추출 (향후 개선)
  - [ ] 상속 관계 추적 (향후 개선)
  - [ ] 어노테이션 정보 (향후 개선)

### Native Discovery
- [x] **unat/discovery/native_discovery.py** ✅
  - [x] .so 파일 파싱
  - [x] Exported 함수 목록
  - [x] Imported 함수 목록
  - [x] 문자열 추출
  - [x] 아키텍처별 처리 (ARM, ARM64, x86)
  - [x] 보안 기능 체크 (PIE, NX, Canary, RELRO)
  - [x] 의존성 추출
  - [x] CLI 통합 (`unat discover --apk`)

### JNI Discovery
- [ ] **unat/discovery/jni_discovery.py**
  - [ ] JNI 함수 탐지
  - [ ] RegisterNatives 추적
  - [ ] JNI 호출 체인 분석

### Frida 스크립트 템플릿
- [x] **frida_scripts/templates/enumerate_classes.js** ✅
  - [x] 로드된 Java 클래스 전체 열거
  - [x] 결과를 Python으로 전송

- [x] **frida_scripts/templates/enumerate_methods.js** ✅
  - [x] 특정 클래스의 메서드/생성자 열거
  - [x] 메서드 시그니처 추출

- [x] **frida_scripts/templates/java_hook.js** ✅
  - [x] 기본 Java 메서드 후킹 템플릿
  - [x] 파라미터/리턴값 로깅
  - [x] Backtrace 출력
  - [x] 다중 오버로드 지원
  - [x] 예외 처리

- [x] **frida_scripts/templates/native_hook.js** ✅
  - [x] Native 함수 후킹 템플릿
  - [x] 레지스터 값 출력
  - [x] 인자 자동 파싱 (int, string, cstring)
  - [x] 멀티 아키텍처 지원 (ARM, ARM64, x86, x64)
  - [x] Backtrace 지원

- [ ] **frida_scripts/templates/jni_hook.js**
  - [ ] JNI 함수 후킹 템플릿
  - [ ] JNI 호출 추적

---

## ✅ [완료] Phase 3 - Hooking 엔진

### Frida 엔진
- [x] **unat/hooking/frida_engine.py** ✅
  - [x] Frida 스크립트 로드 및 실행
  - [x] 스크립트 관리 (시작/중지/재시작)
  - [x] 메시지 핸들링
  - [x] 에러 처리
  - [x] 스크립트 핫 리로드
  - [x] 세션 통계 수집
  - [x] 커스텀 메시지 핸들러 지원

### 후킹 템플릿 관리
- [x] **unat/hooking/hook_templates.py** ✅
  - [x] 템플릿 로드 및 파싱
  - [x] 동적 스크립트 생성
  - [x] 커스텀 템플릿 지원
  - [x] 템플릿 변수 치환
  - [x] Java/Native 후킹 설정 관리

### CLI 명령어 추가
- [x] `unat hook <package> --method <method>` ✅
- [x] `unat hook <package> --native <function>` ✅
- [x] `unat hook <package> --template <template>` ✅
- [x] 추가 옵션: --backtrace, --registers, --no-args, --no-return, -d, -o

---

## 🔄 [대기] Phase 4 - Evasion 모듈

### Anti-Frida 우회
- [ ] **unat/evasion/anti_frida.py**
  - [ ] Frida 탐지 패턴 분석
  - [ ] 자동 우회 스크립트 생성
  - [ ] /proc 기반 탐지 우회
  - [ ] 포트 스캔 탐지 우회

### Anti-Root 우회
- [ ] **unat/evasion/anti_root.py**
  - [ ] Root 탐지 패턴 분석
  - [ ] su 바이너리 숨김
  - [ ] Magisk/SuperSU 탐지 우회

### Anti-Emulator 우회
- [ ] **unat/evasion/anti_emulator.py**
  - [ ] 에뮬레이터 탐지 패턴 분석
  - [ ] 디바이스 속성 조작
  - [ ] IMEI/Serial 조작

---

## 🔄 [대기] Phase 5 - Testing & Fuzzing

### 값 생성기
- [ ] **unat/testing/value_generator.py**
  - [ ] 랜덤 값 생성 (String, Int, Boolean 등)
  - [ ] Edge case 값 생성
  - [ ] 타입 기반 스마트 생성

### 퍼저
- [ ] **unat/testing/fuzzer.py**
  - [ ] 메서드 자동 퍼징
  - [ ] 크래시 탐지
  - [ ] 입력값 뮤테이션
  - [ ] 코드 커버리지 추적

### 취약점 탐지기
- [ ] **unat/testing/vulnerability_detector.py**
  - [ ] 일반적인 취약점 패턴 탐지
  - [ ] SQL Injection 탐지
  - [ ] Path Traversal 탐지
  - [ ] Command Injection 탐지

---

## 🔄 [대기] Phase 6 - Analysis 모듈

### 행동 분석기
- [ ] **unat/analysis/behavior_analyzer.py**
  - [ ] 네트워크 트래픽 추적
  - [ ] 파일 시스템 접근 추적
  - [ ] 데이터베이스 쿼리 로깅
  - [ ] IPC 통신 추적

### 암호화 탐지기
- [ ] **unat/analysis/crypto_detector.py**
  - [ ] 하드코딩된 키 탐지
  - [ ] 취약한 알고리즘 탐지 (DES, MD5 등)
  - [ ] 암호화 API 호출 추적

### 난독화 핸들러
- [ ] **unat/analysis/obfuscation_handler.py**
  - [ ] 패킹 탐지
  - [ ] 문자열 암호화 탐지
  - [ ] 난독화 패턴 분석
  - [ ] 자동 디난독화 시도

---

## 🔄 [대기] Phase 7 - Reporting

### 리포트 생성기
- [ ] **unat/reporting/report_generator.py**
  - [ ] HTML 리포트 생성
  - [ ] JSON 리포트 생성
  - [ ] Markdown 리포트 생성
  - [ ] PDF 리포트 생성 (선택적)

### 시각화
- [ ] **unat/reporting/visualizer.py**
  - [ ] 호출 그래프 생성
  - [ ] 컴포넌트 관계도
  - [ ] 타임라인 차트
  - [ ] 통계 차트

---

## 🔄 [대기] 문서화 & 테스트

### 문서
- [ ] **README.md** 업데이트 (사용법 추가)
- [ ] **docs/INSTALLATION.md** - 설치 가이드
- [ ] **docs/USAGE.md** - 사용 가이드
- [ ] **docs/API.md** - API 문서
- [ ] **docs/EXAMPLES.md** - 예제 모음

### 테스트
- [ ] **tests/test_apk_handler.py** - APK 핸들러 테스트
- [ ] **tests/test_device_manager.py** - 디바이스 관리자 테스트
- [ ] **tests/test_discovery.py** - Discovery 모듈 테스트
- [ ] **tests/test_hooking.py** - Hooking 엔진 테스트

### 예제
- [ ] **examples/analyze_apk.py** - APK 분석 예제
- [ ] **examples/hook_java_method.py** - Java 메서드 후킹 예제
- [ ] **examples/hook_native_function.py** - Native 함수 후킹 예제
- [ ] **examples/bypass_ssl_pinning.py** - SSL Pinning 우회 예제

---

## ✅ [완료] Phase 1 - Core 모듈

### 프로젝트 초기 설정
- [x] 프로젝트 디렉토리 구조 생성
- [x] requirements.txt 작성
- [x] setup.py 작성
- [x] .gitignore 작성
- [x] config/default_config.yaml 작성

### Core 모듈
- [x] **unat/core/apk_handler.py**
  - [x] APK 로드 및 파싱
  - [x] 패키지 정보 추출
  - [x] 권한 분석
  - [x] 컴포넌트 분석
  - [x] 네이티브 라이브러리 추출
  - [x] AndroidManifest.xml 파싱

- [x] **unat/core/device_manager.py**
  - [x] ADB 연결
  - [x] 디바이스 목록
  - [x] Frida 서버 연결
  - [x] APK 설치/제거
  - [x] 액티비티 실행
  - [x] 디바이스 정보 수집

### CLI 인터페이스
- [x] **unat/__main__.py**
  - [x] Click 기반 CLI
  - [x] Rich 라이브러리 통합
  - [x] `unat analyze` 명령어
  - [x] `unat device` 명령어
  - [x] `unat install` 명령어

### 환경 설정
- [x] Python 가상환경 생성
- [x] 의존성 설치
- [x] 개발 모드 패키지 설치

### 작업 관리 시스템
- [x] docs/progress/WORKLOG.md 생성
- [x] docs/progress/TODO.md 생성
- [x] docs/progress/DONE.md 생성
- [x] docs/issues/KNOWN_ISSUES.md 생성

---

## 📊 진행률

```
Phase 1 (Core):             ████████████████████ 100% ✅
Phase 2 (Discovery):        █████████████░░░░░░░  65% 🔄 (Java & Native Discovery 완료, JNI 대기)
Phase 3 (Hooking):          ████████████████████ 100% ✅
Phase 4 (Evasion):          ░░░░░░░░░░░░░░░░░░░░   0%
Phase 5 (Testing):          ░░░░░░░░░░░░░░░░░░░░   0%
Phase 6 (Analysis):         ░░░░░░░░░░░░░░░░░░░░   0%
Phase 7 (Reporting):        ░░░░░░░░░░░░░░░░░░░░   0%

전체 진행률:                ███████████░░░░░░░░░  55%
```

---

## 🎯 다음 우선순위

1. **Evasion 모듈 - Anti-Frida/Root/Emulator 우회** (최우선)
2. **Discovery 모듈 - JNI Discovery** (우선)
3. Testing & Fuzzing 모듈
4. Analysis 모듈
