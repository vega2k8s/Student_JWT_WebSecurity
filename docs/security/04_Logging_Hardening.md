# 04. 보안 감사 로깅 적용 (Logging Hardening)

> OWASP Top 10 2025 **#9 로깅·경보 실패(Logging & Alerting Failures)**
> 브랜치: `feature/logging-hardening`
> 성격: 취약/안전 데모가 아니라, **실제 앱에 보안 로깅을 추가한 하드닝**

---

## 1. 목표

"공격을 기록·감지·대응한다"의 **첫 단계 = 제대로 기록하기**를 실제 앱에 적용한다.

- 로그인 **성공/실패** 기록 (무차별 대입 탐지의 근거)
- **접근 거부(403)·인증 실패(401)** 를 요청 맥락과 함께 기록
- **민감정보(비밀번호·JWT)는 남기지 않기**, 사용자 식별자는 **마스킹**
- `[AUDIT]` 태그로 감사 로그를 구분 (나중에 SIEM 등에서 필터링)

---

## 2. 적용 내용

| 파일 | 변경 | 내용 |
|---|---|---|
| `security/logging/SecurityAuditListener.java` | 신규 | 인증 성공/실패 이벤트 → 감사 로그 (이메일 마스킹) |
| `exception/advice/DefaultExceptionAdvice.java` | 수정 | 401/403 로그에 `[AUDIT]` + 메서드·URI·IP 추가 |
| `application.properties` | 수정 | 감사 로거 레벨(INFO) 지정 |

### 2-1. 인증 이벤트 리스너

```java
@Component
@Slf4j
public class SecurityAuditListener {
    @EventListener
    public void onAuthenticationSuccess(AuthenticationSuccessEvent event) {
        log.info("[AUDIT] 로그인 성공 - user={}", mask(event.getAuthentication().getName()));
    }
    @EventListener
    public void onAuthenticationFailure(AbstractAuthenticationFailureEvent event) {
        log.warn("[AUDIT] 로그인 실패 - user={}, reason={}",
                 mask(event.getAuthentication().getName()),
                 event.getException().getClass().getSimpleName());
    }
    // user@aa.com -> us***@aa.com (민감정보 마스킹)
    private String mask(String value) { ... }
}
```
> Spring Security 가 발행하는 인증 이벤트를 받는다. 폼 로그인·REST 로그인 모두 `AuthenticationManager` 를 거치므로 이벤트가 발생한다.

#### 리스너 클래스 동작 방식

`SecurityAuditListener` 는 별도의 등록 코드 없이 `@Component` 로만 선언돼 있다. 메서드를 직접 호출하는 코드는 어디에도 없는데, 이는 `@EventListener` 가 **Spring 의 ApplicationEvent 발행/구독 메커니즘**에 올라타 있기 때문이다.

- `AuthenticationManager`(정확히는 내부 구현체 `ProviderManager`)가 인증을 처리하고 나면, 결과(성공/실패)에 맞는 이벤트를 `ApplicationEventPublisher` 로 발행한다.
- Spring 컨테이너는 `@EventListener` 가 붙은 메서드의 **파라미터 타입**을 보고, 발행된 이벤트와 타입이 일치(또는 그 이벤트의 상위 타입)하는 모든 빈의 메서드를 찾아 자동으로 호출한다.
- 즉 `SecurityAuditListener` 는 `AuthenticationManager` 를 직접 참조하지 않고도, 인증이 일어나는 모든 경로(폼 로그인, REST 로그인 등)의 결과를 감사 로그로 남길 수 있다. 새로운 로그인 방식이 추가돼도 리스너 코드를 수정할 필요가 없다는 뜻이다.

#### AuthenticationSuccessEvent / AbstractAuthenticationFailureEvent

| 이벤트 | 패키지 | 발행 시점 | 주요 정보 |
|---|---|---|---|
| `AuthenticationSuccessEvent` | `org.springframework.security.authentication.event` | 인증이 성공적으로 완료됐을 때 `ProviderManager` 가 발행 | `getAuthentication()` → 인증된 `Authentication` 객체(사용자명, 권한 등) |
| `AbstractAuthenticationFailureEvent` | `org.springframework.security.authentication.event` | 인증이 실패했을 때, 실패 원인별 **구체 이벤트**(예: `AuthenticationFailureBadCredentialsEvent`, `AuthenticationFailureDisabledEvent`, `AuthenticationFailureLockedEvent`, `AuthenticationFailureExpiredEvent` 등)의 **공통 부모 클래스**로 발행 | `getAuthentication()` → 인증 시도 정보, `getException()` → 실패 원인 예외(`AuthenticationException`) |

- `AbstractAuthenticationFailureEvent` 자체는 추상 클래스이고, 실제로 발행되는 것은 실패 원인에 따른 구체 서브클래스다. 예를 들어 비밀번호 불일치는 `AuthenticationFailureBadCredentialsEvent`, 계정 잠김은 `AuthenticationFailureLockedEvent` 가 발행된다.
- 모두 공통 조상인 `AbstractAuthenticationFailureEvent` 를 상속하므로, 실패 원인은 `event.getException().getClass().getSimpleName()` 으로 구분한다(위 코드의 `reason` 값).

#### `SecurityAuditListener` 는 위 이벤트들의 변동사항을 리스닝하는가?

**그렇다.** `onAuthenticationFailure(AbstractAuthenticationFailureEvent event)` 는 파라미터를 **부모 타입**으로 선언하고 있다. Spring 의 `@EventListener` 는 이벤트의 타입 계층(상속 관계)을 보고 매칭하므로, `AuthenticationFailureBadCredentialsEvent`·`AuthenticationFailureLockedEvent`·`AuthenticationFailureDisabledEvent` 등 **어떤 구체 실패 이벤트가 발행되든** 이 메서드 하나가 전부 수신한다. 마찬가지로 `onAuthenticationSuccess(AuthenticationSuccessEvent event)` 는 인증 성공 이벤트만 수신한다. 따라서 이 리스너는 "인증 성공/실패"라는 두 가지 상태 변화를 **누락 없이** 감사 로그로 남긴다.

### 2-2. 예외 처리 감사 보강 (401/403)

```java
@ExceptionHandler(AccessDeniedException.class)
protected ResponseEntity<ErrorObject> handleException(AccessDeniedException e, HttpServletRequest request) {
    log.warn("[AUDIT] 접근 거부(403) - {} {} from {} : {}",
             request.getMethod(), request.getRequestURI(), clientIp(request), e.getMessage());
    ...
}
```
> 403(접근 거부)은 **권한 상승 시도의 신호**일 수 있어 "누가·무엇을" 함께 남긴다.

### 2-3. `SecurityConfig` 자체의 401/403 처리 — Advice만으로 충분하지 않은 이유

2-2의 `DefaultExceptionAdvice`(`@RestControllerAdvice`)는 401/403을 이미 `[AUDIT]`로 남기고 있다. 그런데도 이후 브랜치들에서는 `SecurityConfig`의 `securityFilterChain`·`formLoginFilterChain` 양쪽에 **또** `[AUDIT]` 로그를 추가했다. 중복이 아니라, **Advice가 아예 호출되지 않는 경로**가 따로 있기 때문이다.

**핵심 원리**: Spring Security의 필터 체인은 `DispatcherServlet`(= Controller, `@RestControllerAdvice`가 동작하는 계층) **이전** 단계에서 실행된다. `.authorizeHttpRequests(...)` 규칙 위반이나 인증 필터의 실패는 필터 체인 안의 `ExceptionTranslationFilter`가 즉시 가로채 그 체인에 설정된 `AuthenticationEntryPoint`(401)·`AccessDeniedHandler`(403)로 응답을 직접 써버린다. 요청이 `DispatcherServlet`까지 도달하지 못하므로, 컨트롤러 메서드 실행 중에만 동작하는 `@RestControllerAdvice`는 이 예외를 **아예 보지 못한다**. 즉 "로그가 Advice에 있으니 됐다"가 아니라, **예외가 발생하는 지점(필터 체인 vs. 컨트롤러 계층)에 따라 둘 중 하나만 호출되므로, 두 지점 모두에 로그를 심어야 누락이 없다.**

**① `securityFilterChain`(API, `/api/**`) — 왜 필요한가**

- 401: `JwtAuthenticationFilter`가 토큰이 없거나 무효하다고 판단하는 순간 발생. 이 필터 자체가 `DispatcherServlet` 이전 단계이므로 Advice는 호출될 수 없다.
- 403: `.requestMatchers("/api/**").authenticated()` 같은 URL 규칙을 `AuthorizationFilter`가 평가해 거부하는 순간 발생. 역시 필터 체인 단계라 Advice에 도달하지 않는다.
  (단, 컨트롤러 메서드에 `@PreAuthorize`로 거는 메서드 보안은 메서드 호출 시점에 평가되므로 `DispatcherServlet`을 통과한 뒤이고, 이 경우의 403은 Advice의 `AccessDeniedException` 핸들러가 정상적으로 캐치한다. 즉 같은 403이라도 **어디서 막혔는지**에 따라 Advice가 보는 것과 못 보는 것이 갈린다.)

```java
.exceptionHandling(ex -> ex
        .authenticationEntryPoint(authenticationEntryPoint())      // 401 → [AUDIT] 로그 + JSON 응답
        .accessDeniedHandler(auditedAccessDeniedHandler()))        // 403 → [AUDIT] 로그 + JSON 응답
```

**② `formLoginFilterChain`(세션/폼 로그인, catch-all) — 왜 필요한가**

- 이 체인은 원래 `exceptionHandling` 자체가 없었다. `/users/**`·`/actuator/**`에 대한 401/403이 Spring Security의 **기본 처리**로 빠지며 `[AUDIT]` 로그가 전혀 남지 않았다. (`securityFilterChain`은 로그가 "Advice에만" 있었던 것과 달리, 이쪽은 **아무 데도** 없었다.)
- 401: 세션 기반이라 실제 응답은 JSON 401이 아니라 `/login`으로의 302 리다이렉트다. 그래도 원인은 "인증 안 된 상태로 보호된 경로에 접근"으로 API 체인의 401과 동일하므로, 같은 `[AUDIT]` 태그로 남기되 응답 자체는 기존 `LoginUrlAuthenticationEntryPoint`에 위임해 리다이렉트 동작은 그대로 유지한다.
- 403: `/actuator/**`를 `ROLE_ADMIN`으로 제한한 규칙을 세션 인증된 사용자가 위반할 때 발생. API 체인과 **동일한** `auditedAccessDeniedHandler()`를 공유해서 쓴다 — 403의 의미(권한 부족)와 응답 형식(JSON)이 같기 때문이다.

```java
.exceptionHandling(ex -> ex
        .authenticationEntryPoint(auditedLoginEntryPoint())        // 401 → [AUDIT] 로그 + /login 리다이렉트(기존 동작 유지)
        .accessDeniedHandler(auditedAccessDeniedHandler()))        // 403 → [AUDIT] 로그 + JSON 응답(API 체인과 공유)
```

**전체 오류 처리 흐름**

```
클라이언트 요청
   │
   ▼
securityMatcher 로 체인 선택 ( "/api/**" → securityFilterChain(@Order 1) ,
                              그 외 전부 → formLoginFilterChain(@Order 2) )
   │
   ▼
[ 필터 체인 내부 ]
  인증 필터 (JwtAuthenticationFilter / 세션+폼 로그인) 통과?
       │ 실패(토큰 없음·무효, 또는 미인증 상태로 보호 경로 접근)
       └──▶ ExceptionTranslationFilter 가 AuthenticationException 포착
                 └──▶ 그 체인에 설정된 AuthenticationEntryPoint 호출
                        → [AUDIT] 인증 실패(401) 로그
                        → 응답 직접 작성 (API: JSON 401 / 폼: /login 리다이렉트)
                        ⚠ DispatcherServlet·Controller·Advice 는 전혀 호출되지 않는다
       │ 통과
       ▼
  인가 필터 (AuthorizationFilter, .authorizeHttpRequests 규칙) 통과?
       │ 거부(인증은 됐지만 권한 부족)
       └──▶ ExceptionTranslationFilter 가 AccessDeniedException 포착
                 └──▶ 그 체인에 설정된 AccessDeniedHandler 호출
                        → [AUDIT] 접근 거부(403) 로그
                        → 응답 직접 작성 (JSON 403)
                        ⚠ 이 경우도 DispatcherServlet·Advice 는 호출되지 않는다
       │ 통과
       ▼
DispatcherServlet → Controller 메서드 실행
       │
       ├─ 메서드 보안(@PreAuthorize 등) 평가 실패 → AccessDeniedException 발생
       │        └──▶ Spring MVC 예외 처리 → @RestControllerAdvice(DefaultExceptionAdvice) 가 캐치
       │                 → [AUDIT] 접근 거부(403) 로그 (2-2 참고) + ResponseEntity 작성
       │
       └─ 로그인 처리 중 자격 증명 불일치 등 → AuthenticationException 발생
                └──▶ 동일하게 DefaultExceptionAdvice 가 캐치 → [AUDIT] 인증 실패(401) 로그
```

**결론**: `[AUDIT] 401/403`이라는 로그 태그는 같지만, **예외가 발생하는 지점이 "필터 체인"이냐 "컨트롤러 계층"이냐에 따라 Advice와 SecurityConfig 중 정확히 한쪽만 호출**된다. 어느 한쪽에만 로그를 남기면 다른 경로로 들어온 401/403은 감사 추적에서 통째로 빠진다. 그래서 두 지점 모두에 `[AUDIT]` 로그를 심어야 한다.

### 2-4. `formLoginFilterChain` 403 응답을 HTML 에러 페이지로

2-3의 `auditedAccessDeniedHandler()`는 403을 JSON으로 응답한다. REST API(`securityFilterChain`)는 이게 맞지만, **브라우저로 접근하는 `formLoginFilterChain`에서는 사용자에게 JSON이 그대로 보이는 게 부자연스럽다.** 그래서 `formLoginFilterChain` 전용으로 `auditedHtmlAccessDeniedHandler()`를 따로 두어, 같은 `[AUDIT]` 로그를 남기되 응답은 HTML 에러 페이지로 분리했다.

```java
private AccessDeniedHandler auditedHtmlAccessDeniedHandler() {
    return (request, response, accessDeniedException) -> {
        log.warn("[AUDIT] 접근 거부(403) - {} {} from {} : {}",
                request.getMethod(), request.getRequestURI(), clientIp(request),
                accessDeniedException.getMessage());
        response.sendError(HttpServletResponse.SC_FORBIDDEN, "접근 권한이 없습니다");
    };
}
```

**동작 원리**: JSON을 직접 작성하는 대신 `response.sendError(403, ...)`을 호출한다. 서블릿 컨테이너는 `sendError()`가 호출되면 그 요청을 `server.error.path`(기본값 `/error`)로 **포워드**하고, Spring Boot의 `BasicErrorController`가 이를 받아 `DefaultErrorViewResolver`로 상태 코드에 맞는 에러 뷰(`error/403`)를 찾는다. 이때 `templates/error/403.html`을 Thymeleaf 템플릿으로 두면(아래), 일반 페이지와 동일하게 **`layout:decorate`로 레이아웃(헤더·네비바·푸터)이 그대로 적용된 채** 렌더링된다. (처음에는 `static/error/403.html`로 만들었으나, 정적 리소스로는 Thymeleaf 레이아웃을 적용할 수 없어 `templates/error/403.html`로 옮겼다.)

```html
<!-- templates/error/403.html -->
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org"
      xmlns:layout="http://www.ultraq.net.nz/thymeleaf/layout" layout:decorate="layout/default_layout">
<meta charset="UTF-8">
<th:block layout:fragment="content">
    <div class="container mt-5 text-center">
        <h1 class="display-4">403</h1>
        <p class="lead">접근 권한이 없습니다.</p>
        <p class="text-muted">이 페이지에 접근하려면 필요한 권한(역할)이 없습니다. 해당 요청은 감사 로그에 기록되었습니다.</p>
        <a href="/" class="btn btn-primary mt-3">홈으로</a>
    </div>
</th:block>
</html>
```

**API 체인은 왜 그대로 JSON인가**: `securityFilterChain`(`/api/**`)의 403은 여전히 `auditedAccessDeniedHandler()`(`writeError()`로 JSON 작성)를 그대로 쓴다. REST API 클라이언트는 HTML 에러 페이지를 파싱할 이유가 없고, JSON 구조(`statusCode`/`message`/`timestamp`)를 기대하기 때문이다. 같은 403이라도 **호출 주체(브라우저 vs API 클라이언트)에 따라 응답 형식을 분리**한 것이지, 로직이나 감사 로그 내용이 달라진 것은 아니다.

> 401(인증 실패)은 `formLoginFilterChain`에서 이미 `/login`으로 리다이렉트되는 것으로 충분한 안내가 되므로, 403과 달리 별도의 `error/401.html`은 만들지 않았다.

---

## 3. 실습 — 감사 로그 확인

앱을 기동한 뒤(예: 8080), 아래를 순서대로 호출하고 콘솔/로그를 본다.

```bash
# 아래 명령들은 전체 URL 사용

# 1) 로그인 실패 (틀린 비밀번호)
curl -s -o /dev/null -w "%{http_code}\n" -X POST "http://localhost:8080/api/userinfos/login" \
  -H "Content-Type: application/json" -d '{"email":"user@aa.com","password":"WRONG"}'

# 2) 로그인 성공 → 토큰 획득
TOKEN=$(curl -s -X POST "http://localhost:8080/api/userinfos/login" \
  -H "Content-Type: application/json" -d '{"email":"user@aa.com","password":"pwd2"}' \
  | sed -n 's/.*"accessToken":"\([^"]*\)".*/\1/p')

# 3) 403 유발 (user가 admin(id=1) 프로필 접근)
curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer $TOKEN" "http://localhost:8080/api/idor/profiles-safe/1"
```

### 실제 출력 (검증됨)

```
[AUDIT] 로그인 실패 - user=us***@aa.com, reason=BadCredentialsException
[AUDIT] 인증 실패(401) - POST /api/userinfos/login from 0:0:0:0:0:0:0:1 : 자격 증명에 실패하였습니다.
[AUDIT] 로그인 성공 - user=us***@aa.com
[AUDIT] 접근 거부(403) - GET /api/idor/profiles-safe/1 from 0:0:0:0:0:0:0:1 : 본인 또는 관리자만 조회할 수 있습니다
```

확인 포인트:
-  이메일이 **`us***@aa.com`** 로 마스킹됨 (원본 노출 안 함)
-  **비밀번호·JWT 토큰은 로그에 전혀 없음**
-  401/403에 **메서드·URI·출처 IP** 포함 → "누가 무엇을" 파악 가능
-  `[AUDIT]` 태그로 감사 로그만 골라볼 수 있음

### 3-1. 단계별 로그와 grep 확인

여러 요청을 한 번에 보내면 로그가 섞인다. **요청을 하나씩 보내고, 해당 요청의 로그만 grep으로 확인**한다. (각 명령은 전체 URL을 그대로 사용)

**① 로그인 실패 (틀린 비밀번호) → HTTP 401**
```bash
curl -s -o /dev/null -X POST "http://localhost:8080/api/userinfos/login" \
  -H "Content-Type: application/json" -d '{"email":"user@aa.com","password":"WRONG"}'
```
출력 로그 (2줄):
```
[AUDIT] 로그인 실패 - user=us***@aa.com, reason=BadCredentialsException
[AUDIT] 인증 실패(401) - POST /api/userinfos/login from ...::1 : 자격 증명에 실패하였습니다.
```
확인:
```bash
grep -E "로그인 실패|인증 실패" logs/spring.log | tail -2
```

**② 로그인 성공 → HTTP 200 (토큰 발급)**
```bash
curl -s -X POST "http://localhost:8080/api/userinfos/login" \
  -H "Content-Type: application/json" -d '{"email":"user@aa.com","password":"pwd2"}'
```
출력 로그 (1줄):
```
[AUDIT] 로그인 성공 - user=us***@aa.com
```
확인:
```bash
grep "로그인 성공" logs/spring.log | tail -1
```

**③ 접근 거부 (user가 admin 프로필) → HTTP 403** (위 ②에서 받은 `TOKEN` 사용)
```bash
curl -s -o /dev/null -H "Authorization: Bearer $TOKEN" "http://localhost:8080/api/idor/profiles-safe/1"
```
출력 로그 (1줄):
```
[AUDIT] 접근 거부(403) - GET /api/idor/profiles-safe/1 from ...::1 : 본인 또는 관리자만 조회할 수 있습니다
```
확인:
```bash
grep "접근 거부" logs/spring.log | tail -1
```

> **참고**: 2줄이 나오는 건 ①(실패)뿐이다. ②는 1줄(성공), ③도 1줄(403). 전체를 한 번에 보려면 `grep "\[AUDIT\]" logs/spring.log`.

---

## 4. 여기까지가 "탐지"의 토대

이번 실습은 로깅·경보 5단계 중 **① 기록**에 해당한다. 이후 단계는 개념으로 이해한다:

| 단계 | 내용 | 이 앱 |
|---|---|---|
| ① 기록 | 중요한 것 남기고, 민감정보는 빼기 |  이번 적용 |
| ② 중앙 집중 | SIEM·ELK로 로그 모으기 | 개념 |
| ③ 탐지·경보 | 다수 로그인 실패=무차별 대입 등 규칙 | 개념 |
| ④ 보관·보호 | 90~180일+, append-only 무결성 | 개념 |
| ⑤ 대응 연계 | 경보→플레이북/SOAR | 개념 |

> 예: 이후 CSRF·무차별 대입 데모에서 **"공격이 `[AUDIT]` 로그에 이렇게 남는다"** 를 함께 보여줄 수 있다.

---

## 5. 예외 처리 하드닝 (OWASP #10)

#9(로깅)와 짝을 이루는 **#10(예외 상황 처리 미흡)** 대응. 예외 발생 시 내부 정보를 노출하지 않고(**fail-closed**), 외부엔 일반 메시지+traceId, 내부 로그엔 상세를 남긴다.

### 5-1. 무엇을 바꿨나 (`DefaultExceptionAdvice`)
- **500(RuntimeException)** → 일반 메시지+traceId (`e.getMessage()` 숨김)
- **catch-all** `@ExceptionHandler(Exception.class)` → 안 잡힌 예외도 fail-closed 500
- **400 파싱 오류**도 일반화(파서 상세 숨김)
- `server.error.include-*=never` (층 1 기본 오류 처리기 명시)

```java
private ResponseEntity<ErrorObject> internalError(Exception e, HttpServletRequest request) {
    String traceId = newTraceId();
    // 내부 로그: 상세 + traceId
    log.error("[ERROR][{}] {} {} : {}", traceId, request.getMethod(), request.getRequestURI(), e.getMessage(), e);
    // 외부 응답: 일반 메시지 + traceId (내부 메시지 숨김)
    errorObject.setMessage("서버 내부 오류가 발생했습니다. (traceId: " + traceId + ")");
    ...
}
```

### 5-2. 실습 — 500 오류 하드닝 확인

깨진 SQL 페이로드(단일 따옴표)로 500을 유발하고, 외부 응답과 내부 로그를 비교한다.
```bash
curl -s -w "\n[HTTP %{http_code}]\n" "http://localhost:8080/api/vuln/sqli/students?name=%27"
```
**외부 응답** (일반 메시지+traceId, SQL 상세 없음):
```json
{"statusCode":500,"message":"서버 내부 오류가 발생했습니다. (traceId: 9a51a868)", ...}
```
**내부 로그** (상세 + 동일 traceId):
```
[ERROR][9a51a868] GET /api/vuln/sqli/students : bad SQL grammar [SELECT ... WHERE name LIKE '%'%']
```
```bash
grep "\[ERROR\]" logs/spring.log | tail -1
```

> **핵심**: `traceId`로 외부 응답과 내부 로그가 연결되며, 외부엔 SQL 내부 구조가 노출되지 않는다. (하드닝 전엔 `e.getMessage()`가 응답에 담겨 SQL 오류가 그대로 노출됐다.)

---

## 6. 관련 문서

- OWASP Top 10 2025 #9 로깅 보충 / #10 오류 메시지 숨김의 두 층
- 접근 거부(403)가 나온 IDOR: `02_Insecure_DOR`
