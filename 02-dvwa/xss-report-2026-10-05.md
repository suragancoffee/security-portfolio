# DVWA XSS (Cross-Site Scripting) 취약점 점검 — 2026-10-05

## 개요

DVWA를 대상으로 Reflected XSS와 Stored XSS를 Low/Medium 난이도에서 점검하였다.
두 취약점 모두 Low에서 즉시 성공하였고, Medium에서도 필터의 허점(필드별 방어
수준 차이, HTML `maxlength` 속성)을 분석하여 우회에 성공하였다.

| 구분 | 내용 |
|---|---|
| 점검 대상 | DVWA (localhost:8080, Docker 컨테이너) |
| 점검일 | 2026-10-05 |
| 점검자 | 이기원 |
| 대상 페이지 | `/vulnerabilities/xss_r/` (Reflected), `/vulnerabilities/xss_s/` (Stored) |
| 위험도 | Critical |

---

## [Critical] Cross-Site Scripting (XSS) — Reflected / Stored (Low / Medium)

### 설명
DVWA의 XSS 페이지는 사용자 입력값을 충분히 이스케이프하지 않고 HTML 응답에
그대로 포함시킨다. Reflected XSS는 입력값이 요청 즉시 응답에 반영되어 실행되는
형태이고, Stored XSS는 입력값이 DB(방명록)에 저장되어 **이후 해당 페이지를
방문하는 모든 사용자에게 반복적으로 실행**되는 더 위험한 형태이다. Medium
레벨은 필드별로 서로 다른 방식의 방어를 적용하고 있었으나, 모두 우회가
가능함을 확인하였다.

### 재현 절차

**[Low 레벨 — Reflected XSS]**

1. **기본 실행 확인**
   ```
   입력값 (name 파라미터): <script>alert('XSS')</script>
   ```
   → 입력 즉시 `XSS` 알림창이 실행됨
   > [스크린샷 삽입: Reflected XSS - alert('XSS') 팝업]

2. **세션 쿠키 탈취 시나리오 검증**
   ```
   입력값: <script>alert(document.cookie)</script>
   ```
   → 실제 세션 쿠키 값이 그대로 노출됨
   ```
   PHPSESSID=r78qv8akqb9habn69dbqt4sff1; security=low
   ```
   → 실제 공격에서는 이 값을 외부 서버로 전송하여 세션을 탈취하고,
   로그인 없이 피해자로 위장할 수 있다.
   > [스크린샷 삽입: document.cookie 노출 결과]

**[Low 레벨 — Stored XSS]**

3. **방명록에 스크립트 저장**
   ```
   Name: 홍길동
   Message: <script>alert('Stored XSS')</script>
   ```
   → 등록 즉시 알림창 실행
   > [스크린샷 삽입: Stored XSS 등록 시 alert 팝업]

4. **영구 저장 여부 확인**
   입력을 다시 하지 않고 메뉴에서 "XSS (Stored)" 페이지를 재방문
   → **입력 없이 페이지에 진입만 해도 알림창이 자동 실행됨**을 확인
   → 악성 스크립트가 DB에 영구 저장되어, 이 방명록을 보는 모든 사용자가
   공격 대상이 됨을 의미
   > [스크린샷 삽입: 재방문 시 자동 실행되는 팝업]

**[Medium 레벨 — 우회 테스트]**

5. **Medium 전환 및 기본 페이로드 재시도**
   ```
   Message: <script>alert('XSS')</script>
   ```
   → Message 필드는 `strip_tags()` 방식으로 거의 모든 HTML 태그를 제거하여
   `<script>` 태그가 완전히 사라지고 텍스트만 남음 (1차 방어는 유효)
   > [스크린샷 삽입: Medium - script 태그 필터링된 결과]

6. **필드별 방어 수준 차이 분석**
   동일한 페이로드를 **Name 필드**에 입력 시, 태그 자체는 필터링되지 않고
   남아있음을 확인 (Name 필드는 `<script>` 문자열만 단순 치환하는 약한 필터)
   ```
   Name: <svg onload=alert(1)>
   Message: test
   ```
   → 그러나 알림창은 실행되지 않음 → **원인 분석 필요**

7. **원인 분석: 브라우저 페이지 소스 확인**
   `Ctrl+U`로 페이지 소스를 확인한 결과, 저장된 값이 다음과 같이 **잘려
   있음**을 발견
   ```html
   <div id="guestbook_comments">Name: <svg onloa<br />Message: test<br /></div>
   ```
   → `<input name="txtName" ... maxlength="10">` 속성으로 인해 입력값이
   10자에서 강제로 잘린 것이 원인이었음 (필터링이 아닌 **HTML 입력 길이
   제한**이 원인)
   > [스크린샷 삽입: 페이지 소스에서 payload가 잘려있는 부분]

8. **maxlength 우회 (브라우저 개발자 도구 사용)**
   `maxlength`는 클라이언트 측(HTML) 제약일 뿐 서버 측 검증이 아니므로,
   개발자 도구(F12 → Inspector)로 해당 속성을 직접 수정하여 우회
   ```
   maxlength="10" → maxlength="200"
   ```
   > [스크린샷 삽입: 개발자 도구에서 maxlength 속성 수정 전/후]

9. **우회 성공**
   속성 수정 후 동일 페이로드 재입력
   ```
   Name: <svg onload=alert(1)>
   Message: test
   ```
   → **알림창(`1`) 실행 성공**, Medium 레벨의 Name 필드 방어를 완전히 우회
   > [스크린샷 삽입: maxlength 우회 후 alert(1) 팝업 성공]

### 영향 (Impact)
- Reflected XSS: 피해자가 악성 링크를 클릭하는 즉시 임의 스크립트 실행,
  세션 쿠키 등 민감 정보 탈취 가능
- Stored XSS: 공격자가 한 번만 페이로드를 심으면 이후 해당 페이지를 방문하는
  **모든 사용자**가 별도 조작 없이 공격당함 (피싱 페이지 삽입, 키로깅,
  세션 탈취 등으로 확장 가능)
- Medium 레벨 분석 결과, 입력 필드별로 방어 수준이 불균일했으며(Message는
  강한 필터, Name은 약한 필터 + 길이 제한), **길이 제한(maxlength)과 같은
  클라이언트 측 HTML 속성은 개발자 도구만으로 손쉽게 우회**되어 실질적인
  보안 통제로 볼 수 없음

### 대응 방안 (Remediation)
1. 출력 시 **컨텍스트에 맞는 이스케이프** 적용 (HTML 엔티티 인코딩: `<`, `>`,
   `"`, `'`, `&` 등)
2. 입력 필터링은 **화이트리스트 기반**으로 설계하고, 모든 필드에 **동일하고
   일관된 수준**의 검증 적용 (필드별로 방어 수준이 다르면 가장 약한 지점이
   전체 취약점이 됨)
3. `maxlength` 등 HTML 속성은 사용자 경험(UX) 개선용일 뿐 보안 통제가 아님을
   인지하고, **서버 측에서도 동일한 길이/형식 검증**을 반드시 재적용
4. Content-Security-Policy(CSP) 헤더를 적용하여 인라인 스크립트 실행 자체를
   차단
5. 세션 쿠키에 `HttpOnly`, `Secure`, `SameSite` 속성을 설정하여 스크립트를
   통한 쿠키 탈취 가능성을 원천적으로 차단

---

## 오늘의 핵심 요약

| 번호 | 취약점명 | 난이도 | 위험도 |
|---|---|---|---|
| 1 | Reflected XSS (쿠키 노출) | Low | Critical |
| 2 | Stored XSS (영구 저장) | Low | Critical |
| 3 | Stored XSS (maxlength 우회) | Medium | Critical |

**핵심 교훈**: 클라이언트 측에서만 적용되는 제한(HTML `maxlength` 속성 등)은
실질적인 보안 대책이 될 수 없으며, 개발자 도구만으로 쉽게 우회된다. 서버 측
검증과 적절한 이스케이프 처리가 반드시 병행되어야 한다.

---

## 부록

- 대상 파라미터
  - `name` (`/vulnerabilities/xss_r/`)
  - `txtName`, `mtxMessage` (`/vulnerabilities/xss_s/`)
- 사용 페이로드
  - `<script>alert('XSS')</script>`
  - `<script>alert(document.cookie)</script>`
  - `<svg onload=alert(1)>`
- 참고 자료
  - OWASP Top 10 2021 – A03:2021 Injection
  - OWASP XSS Filter Evasion Cheat Sheet
  - DVWA 공식 문서

---

> 📌 이 파일은 02-dvwa/report.md의 "4.2 XSS" 섹션과 동일한 내용입니다.
> 전체 보고서(SQL Injection 포함)에 합치려면 report.md를 사용하세요.
