# Security Portfolio

정보통신공학과 학생의 정보보안(모의해킹) 학습 포트폴리오입니다.
직접 구축한 가상 환경에서 취약점을 발견하고, 공격을 재현한 뒤,
전문 모의해킹 보고서 형식으로 정리하는 것을 목표로 합니다.

## About Me

- 소속: [명지대학교] 정보통신공학과 
- 관심 분야: 모의해킹(Penetration Testing), 웹 보안, 네트워크 보안
- 목표: 보안관제 / 모의해킹 직무 취업
- Contact: 2ggg2000@7gmail.com

## 학습 환경

- VMware Workstation Pro 17
- Kali Linux (공격자)
- 점검 대상: Metasploitable2, DVWA, Juice Shop 등 공개 취약 환경
- 모든 네트워크는 Host-only로 격리하여 외부와 분리된 폐쇄 환경에서만 실습

> ⚠️ 본 저장소의 모든 점검은 학습 목적으로 공개된 취약 환경(Metasploitable2,
> DVWA, HTB, TryHackMe 등)에서만 수행되었으며, 실제 서비스나 제3자 시스템에
> 대한 무단 점검은 포함하지 않습니다.

## 프로젝트 목록

| # | 프로젝트 | 대상 | 주요 내용 | 링크 |
|---|---|---|---|---|
| 01 | Metasploitable2 취약점 점검 | Metasploitable2 | VSFTPD 백도어(CVE-2011-2523) 침투, 권한 획득 | [report.md](./01-metasploitable2/report1.md) |
| 02 | SQL Injection 취약점 점검 | DVWA | SQL Injection(인증 우회, UNION 추출), 해시 크랙, 난이도별 비교 | [report.md](./02-dvwa/report1.md) |
| 03 | (추가 예정) | HTB/THM | 머신 풀이 write-up | - |

## 사용 도구

`Nmap` `Metasploit Framework` `Burp Suite` `Wireshark` `Kali Linux`

## 자격증 및 활동

- [정보보안기사 / 정보처리기사 등]
