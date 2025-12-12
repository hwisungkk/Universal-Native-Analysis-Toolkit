/**
 * JNI Discovery Script - JNI 함수 동적 탐지 스크립트
 *
 * ## 목적:
 * Android 앱의 JNI 함수와 RegisterNatives 호출을 런타임에 탐지합니다.
 *
 * ## 탐지 대상:
 * 1. **RegisterNatives 호출**: Dynamic JNI 매핑 (Java 메서드 → Native 함수)
 * 2. **Native 메서드 열거**: Reflection으로 native 키워드가 있는 메서드 탐색
 *
 * ## JNI 브릿지 종류:
 * - **Static JNI**: Java_com_example_ClassName_methodName 이름 규칙
 * - **Dynamic JNI**: RegisterNatives로 임의의 함수 이름 매핑 (난독화에 사용)
 *
 * ## 출력 정보:
 * - Java 클래스 및 메서드 이름
 * - JNI 시그니처 (예: "(I)V")
 * - Native 함수 주소 (메모리 주소)
 */

Java.perform(function() {
    console.log("[*] JNI Discovery started");

    var jniMethods = [];  // 열거로 발견한 native 메서드
    var registerNativesCalls = [];  // RegisterNatives 호출 목록

    // RegisterNatives 후킹 - Dynamic JNI 매핑 가로채기
    // JNI_OnLoad에서 호출되는 RegisterNatives를 후킹하여 매핑 정보 추출
    try {
        var env = Java.vm.getEnv();  // JNIEnv 포인터 획득
        var RegisterNatives = env.registerNatives;

        if (RegisterNatives) {
            Interceptor.attach(RegisterNatives.implementation, {
                onEnter: function(args) {
                    try {
                        // RegisterNatives 함수 시그니처:
                        // jint RegisterNatives(JNIEnv* env, jclass clazz,
                        //                      const JNINativeMethod* methods, jint nMethods)
                        //
                        // args[0] = JNIEnv* (환경 포인터)
                        // args[1] = jclass (Java 클래스 객체)
                        // args[2] = JNINativeMethod* (메서드 배열 포인터)
                        // args[3] = jint (등록할 메서드 개수)

                        var className = null;
                        var methods = [];
                        var nMethods = args[3].toInt32();

                        // Java 클래스 이름 추출
                        try {
                            var jclass = Java.cast(args[1], Java.use("java.lang.Class"));
                            className = jclass.getName();
                        } catch (e) {
                            className = "<unknown>";
                        }

                        // JNINativeMethod 배열 파싱
                        // C 구조체를 메모리에서 직접 읽어 정보 추출
                        if (nMethods > 0 && nMethods < 100) {  // 유효성 검사 (너무 큰 값 방지)
                            var methodsArray = args[2];

                            for (var i = 0; i < nMethods; i++) {
                                try {
                                    // JNINativeMethod 구조체 레이아웃:
                                    // struct {
                                    //     const char* name;       // +0 (메서드 이름)
                                    //     const char* signature;  // +4/+8 (JNI 시그니처)
                                    //     void* fnPtr;            // +8/+16 (함수 포인터)
                                    // };
                                    //
                                    // 32비트: 각 포인터 4바이트 → 구조체 크기 12바이트
                                    // 64비트: 각 포인터 8바이트 → 구조체 크기 24바이트

                                    var offset = Process.pointerSize === 8 ? i * 24 : i * 12;
                                    var methodStruct = methodsArray.add(offset);

                                    // 구조체 필드 읽기
                                    var namePtr = methodStruct.readPointer();  // name 포인터 읽기
                                    var sigPtr = methodStruct.add(Process.pointerSize).readPointer();  // signature
                                    var fnPtr = methodStruct.add(Process.pointerSize * 2).readPointer();  // fnPtr

                                    // C 문자열 읽기
                                    var methodName = namePtr.readCString();
                                    var methodSig = sigPtr.readCString();

                                    methods.push({
                                        name: methodName,
                                        signature: methodSig,
                                        address: fnPtr.toString()
                                    });
                                } catch (e) {
                                    console.log("[-] Error reading method " + i + ": " + e);
                                }
                            }
                        }

                        // Python으로 결과 전송
                        var registrationInfo = {
                            type: 'jni_register',
                            className: className,
                            methodCount: nMethods,
                            methods: methods,
                            timestamp: new Date().toISOString()
                        };

                        registerNativesCalls.push(registrationInfo);
                        send(registrationInfo);  // Python의 on_message 핸들러로 전송

                        console.log("[+] RegisterNatives: " + className + " (" + nMethods + " methods)");
                        methods.forEach(function(m) {
                            console.log("    - " + m.name + m.signature + " @ " + m.address);
                        });

                    } catch (e) {
                        console.log("[-] Error in RegisterNatives hook: " + e);
                    }
                }
            });

            console.log("[+] RegisterNatives hook installed");
        }
    } catch (e) {
        console.log("[-] Failed to hook RegisterNatives: " + e);
    }

    // Enumerate all loaded classes and find native methods
    function enumerateNativeMethods() {
        console.log("[*] Enumerating native methods...");

        Java.enumerateLoadedClasses({
            onMatch: function(className) {
                try {
                    var clazz = Java.use(className);

                    // Get all declared methods
                    var methods = clazz.class.getDeclaredMethods();

                    methods.forEach(function(method) {
                        try {
                            var modifiers = method.getModifiers();
                            // Check if method is native (0x100 = NATIVE modifier)
                            if ((modifiers & 0x100) !== 0) {
                                var methodInfo = {
                                    type: 'native_method',
                                    className: className,
                                    methodName: method.getName(),
                                    signature: method.toString(),
                                    modifiers: modifiers.toString(16)
                                };

                                jniMethods.push(methodInfo);

                                console.log("[+] Native method: " + className + "." + method.getName());
                            }
                        } catch (e) {
                            // Skip methods that throw exceptions
                        }
                    });

                } catch (e) {
                    // Skip classes that cannot be loaded
                }
            },
            onComplete: function() {
                console.log("[*] Native method enumeration complete");
                console.log("[*] Found " + jniMethods.length + " native methods");

                send({
                    type: 'jni_summary',
                    nativeMethods: jniMethods,
                    registerNativesCalls: registerNativesCalls,
                    totalNativeMethods: jniMethods.length,
                    totalRegistrations: registerNativesCalls.length
                });
            }
        });
    }

    // Start enumeration after a short delay
    setTimeout(enumerateNativeMethods, 2000);

    console.log("[*] JNI Discovery initialized");
});
