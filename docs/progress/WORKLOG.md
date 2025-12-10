# UNAT 개발 작업 로그

## 작업 규칙
- 매 작업 시작 시: TODO.md 업데이트
- 작업 중: WORKLOG.md에 로그 추가
- 작업 완료: DONE.md에 상세 기록
- 문제 발견: KNOWN_ISSUES.md에 기록

---

## 2024-12-10 - Phase 2-1: Java Discovery 구현

### 작업 내용
Discovery 모듈의 첫 번째 구현: Java 클래스 및 메서드 탐색 기능

### 완료 항목
1. **Java Discovery 모듈**
   - `unat/discovery/java_discovery.py` (약 400줄)
     - JavaDiscovery 클래스 구현
     - Frida 세션 연결 (attach/spawn)
     - Java 클래스 열거 (Java.enumerateLoadedClasses)
     - 메서드 열거 (getDeclaredMethods)
     - 난독화 패턴 인식
     - 필터링 기능 (패키지, 난독화, 시스템 클래스)
     - JavaClassInfo, JavaDiscoveryResult 데이터 클래스

2. **Frida 스크립트 템플릿**
   - `frida_scripts/templates/enumerate_classes.js`
     - 로드된 Java 클래스 전체 열거
     - 결과를 Python으로 전송

   - `frida_scripts/templates/enumerate_methods.js`
     - 특정 클래스의 메서드/생성자 열거
     - 메서드 시그니처 추출

3. **CLI 통합**
   - `unat discover` 명령어 추가
     - `--spawn`: 앱 실행 및 attach
     - `--package-only`: 앱 패키지 클래스만 (기본값)
     - `--filter-obfuscated`: 난독화된 클래스만 표시
     - `--no-methods`: 메서드 열거 스킵 (빠른 스캔)
     - `-o, --output`: JSON 형식 결과 저장
     - `--max-classes`: 처리할 최대 클래스 수

   - Rich 테이블로 결과 표시
     - 클래스 이름, 메서드 수, 난독화 여부
     - 난독화된 클래스는 빨간색 표시
     - 예제 메서드 표시

### 주요 기능
- **난독화 탐지 패턴**
  - 단일 문자 클래스명 (a, b, c)
  - 짧은 클래스명 (ab, o0, l1l)
  - O0O, III 같은 혼동 패턴
  - 짧은 패키지 이름

- **성능 최적화**
  - 메서드 열거 선택적 스킵
  - 최대 클래스 수 제한
  - 진행 상황 로깅

### 테스트 완료
- ✅ `unat discover --help` - 도움말 출력 정상
- ✅ CLI 명령어 구조 확인
- ✅ 문법 오류 수정

### 다음 작업
- Native Discovery 구현 (.so 파일 분석)
- JNI Discovery 구현
- 실제 APK로 테스트 (InsecureShop, 난독화된 앱)

### 작업 시간
약 1.5시간 (설계 + 구현 + 테스트)

### 참고 사항
- Frida의 Java.enumerateLoadedClasses() API 사용
- 인라인 스크립트 fallback 제공 (템플릿 파일 없어도 작동)
- 난독화 탐지는 휴리스틱 기반 (100% 정확하지 않음)

---

## 2024-12-10 - Phase 1 완료

### 작업 내용
Phase 1 핵심 모듈 구현 및 초기 설정 완료

### 완료 항목
1. **프로젝트 구조 생성**
   - unat/ 메인 패키지 및 하위 모듈 디렉토리 생성
   - frida_scripts/, tests/, examples/, config/, output/ 디렉토리 생성

2. **설정 파일**
   - requirements.txt - 프로젝트 의존성 정의
   - setup.py - 패키지 설치 설정
   - .gitignore - Python + Windows + 프로젝트 특화 항목
   - config/default_config.yaml - 전체 설정 파일

3. **Phase 1 구현: Core 모듈**
   - `unat/core/apk_handler.py` (약 350줄)
     - APK 로드 및 파싱
     - 패키지 정보 추출
     - 권한 및 컴포넌트 분석
     - 네이티브 라이브러리 추출 (아키텍처별)
     - AndroidManifest.xml 파싱

   - `unat/core/device_manager.py` (약 350줄)
     - ADB 연결 및 디바이스 관리
     - Frida 서버 연결 확인
     - APK 설치/제거 기능
     - 액티비티 실행
     - 디바이스 정보 수집

   - `unat/__main__.py` (약 350줄)
     - Click 기반 CLI 인터페이스
     - Rich 라이브러리로 컬러풀한 출력
     - analyze, device, install 명령어 구현

4. **환경 설정**
   - Python 가상환경 생성 (venv)
   - 모든 의존성 설치 완료
   - 개발 모드로 패키지 설치 (pip install -e .)

### 테스트 완료
- ✅ `unat --help` - 도움말 출력 정상
- ✅ `unat analyze --help` - APK 분석 명령어 도움말 정상
- ✅ `unat device --help` - 디바이스 명령어 도움말 정상
- ✅ `unat install --help` - 설치 명령어 도움말 정상

### 다음 작업
- Discovery 모듈 구현 (Java/Native 함수 탐색)
- Frida 스크립트 템플릿 작성

### 작업 시간
약 3시간 (설계 + 구현 + 테스트)

### 참고 사항
- 모든 핵심 기능은 Androguard, Frida 라이브러리 기반
- Windows 환경에서 개발 및 테스트
- Python 3.8+ 호환

---

## 작업 템플릿

```markdown
## YYYY-MM-DD - [작업 제목]

### 작업 내용
[작업 설명]

### 완료 항목
- [항목 1]
- [항목 2]

### 테스트 완료
- ✅ [테스트 항목 1]
- ✅ [테스트 항목 2]

### 다음 작업
- [다음 작업 1]
- [다음 작업 2]

### 이슈/문제점
- [발견된 문제나 개선 사항]

### 작업 시간
[소요 시간]

---
```
