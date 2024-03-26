# CIC-IDS-attack-detection
AI프레임워크 보안 1주차 수행과제
해당 데이터 셋은 https://www.unb.ca/cic/datasets/ids-2017.html

dddd
<pre>
TCP/UDP 포트 번호 중 목적지 포트 번호
Flow Duration: 플로우 지속 시간
Total Fwd Packets: 전방 패킷 총 수
Total Backward Packets: 후방 패킷 총 수
Total Length of Fwd Packets: 전방 패킷의 총 길이
Total Length of Bwd Packets: 후방 패킷의 총 길이
Fwd Packet Length Max: 전방 패킷의 최대 길이
Fwd Packet Length Min: 전방 패킷의 최소 길이
Fwd Packet Length Mean: 전방 패킷의 평균 길이
Fwd Packet Length Std: 전방 패킷의 길이 표준편차
Bwd Packet Length Max: 후방 패킷의 최대 길이
Bwd Packet Length Min: 후방 패킷의 최소 길이
Bwd Packet Length Mean: 후방 패킷의 평균 길이
Bwd Packet Length Std: 후방 패킷의 길이 표준편차
Flow Bytes/s: 플로우의 바이트 속도
Flow Packets/s: 플로우의 패킷 속도
Flow IAT Mean: 플로우 IAT의 평균
Flow IAT Std: 플로우 IAT의 표준편차
Flow IAT Max: 플로우 IAT의 최대
Flow IAT Min: 플로우 IAT의 최소
Fwd IAT Total: 전방 IAT의 총합
Fwd IAT Mean: 전방 IAT의 평균
Fwd IAT Std: 전방 IAT의 표준편차
Fwd IAT Max: 전방 IAT의 최대
Fwd IAT Min: 전방 IAT의 최소
Bwd IAT Total: 후방 IAT의 총합
Bwd IAT Mean: 후방 IAT의 평균
Bwd IAT Std: 후방 IAT의 표준편차
Bwd IAT Max: 후방 IAT의 최대
Bwd IAT Min: 후방 IAT의 최소
Fwd PSH Flags: 전방 PSH 플래그 수
Bwd PSH Flags: 후방 PSH 플래그 수
Fwd URG Flags: 전방 URG 플래그 수
Bwd URG Flags: 후방 URG 플래그 수
Fwd Header Length: 전방 헤더의 길이
Bwd Header Length: 후방 헤더의 길이
Fwd Packets/s: 전방 패킷 속도
Bwd Packets/s: 후방 패킷 속도
Min Packet Length: 최소 패킷 길이
Max Packet Length: 최대 패킷 길이
Packet Length Mean: 패킷 길이의 평균
Packet Length Std: 패킷 길이의 표준편차
Packet Length Variance: 패킷 길이의 분산
FIN Flag Count: FIN 플래그의 수
SYN Flag Count: SYN 플래그의 수 
RST Flag Count: RST 플래그의 수
PSH Flag Count: PSH 플래그의 수
ACK Flag Count: ACK 플래그의 수
URG Flag Count: URG 플래그의 수
CWE Flag Count: CWE 플래그의 수
ECE Flag Count: ECE 플래그의 수
Down/Up Ratio: 다운로드/업로드 비율
Average Packet Size: 평균 패킷 크기
Avg Fwd Segment Size: 평균 전방 세그먼트 크기
Avg Bwd Segment Size: 평균 후방 세그먼트 크기
Fwd Header Length.1: 전방 헤더의 길이
Fwd Avg Bytes/Bulk: 전방의 평균 바이트/대량
Fwd Avg Packets/Bulk: 전방의 평균 패킷/대량
Fwd Avg Bulk Rate: 전방의 평균 대량 속도
Bwd Avg Bytes/Bulk: 후방의 평균 바이트/대량
Bwd Avg Packets/Bulk: 후방의 평균 패킷/대량
Bwd Avg Bulk Rate: 후방의 평균 대량 속도
Subflow Fwd Packets: 하위 플로우의 전방 패킷 수
Subflow Fwd Bytes: 하위 플로우의 전방 바이트 수
Subflow Bwd Packets: 하위 플로우의 후방 패킷 수
Subflow Bwd Bytes: 하위 플로우의 후방 바이트 수
Init_Win_bytes_forward: 초기 윈도우 바이트 전방
Init_Win_bytes_backward: 초기 윈도우 바이트 후방
act_data_pkt_fwd: 전방 데이터 패킷
min_seg_size_forward: 전방 최소 세그먼트 크기
Active Mean: 활성 상태의 평균
Active Std: 활성 상태의 표준편차
Active Max: 활성 상태의 최대
Active Min: 활성 상태의 최소
Idle Mean: 유휴 상태의 평균
Idle Std: 유휴 상태의 표준편차
Idle Max: 유휴 상태의 최대
Idle Min: 유휴 상태의 최소
Label: 네트워크 트래픽 종류
</pre>

Label
<pre>
BENIGN: 정상적인 네트워크 트래픽입니다.
  
DoS Hulk: Hulk는 대규모 DDoS(분산 서비스 거부) 공격 유형 중 하나입니다. 이 유형의 공격은 대상 서버에 대량의 HTTP GET 또는 POST 요청을 보내어 서버 리소스를 고갈시키는 것을 목표로 합니다.
  
PortScan: 공격자가 대상 네트워크 또는 컴퓨터에 대해 여러 포트에 대한 접근 가능성을 탐지하는 시도를 수행합니다. 이는 네트워크 침입의 초기 단계로 사용될 수 있습니다.
  
DDoS: 분산 서비스 거부(DDoS) 공격은 여러 소스에서 공동으로 대상 시스템에 대량의 트래픽을 보내어 시스템을 다운시키는 공격입니다.
  
DoS GoldenEye: GoldenEye는 HTTP Flood DDoS 공격의 한 유형입니다. 이 유형의 공격은 다수의 공격자가 대상 서버에 대량의 HTTP GET 또는 POST 요청을 보내는 것을 목표로 합니다.
  
FTP-Patator: FTP-Patator는 대상 FTP 서버에 대해 사전 인증을 사용하여 암호를 찾는 공격입니다.
  
SSH-Patator: SSH-Patator는 대상 SSH 서버에 대해 사전 인증을 사용하여 암호를 찾는 공격입니다.
  
DoS slowloris: Slowloris는 웹 서버를 대상으로 하는 DoS 공격 유형 중 하나로, 공격자가 웹 서버에 여러 연결을 유지하고 연결을 끊지 않은 채로 보내는 요청을 보냄으로써 서버의 연결 가능한 스레드를 모두 점유하는 것을 목표로 합니다.
  
DoS Slowhttptest: Slowhttptest는 Slowloris와 유사하지만 HTTP 요청을 사용하여 웹 서버를 대상으로 하는 DoS 공격입니다.
  
Bot: 시스템을 감염시켜 원격에서 제어할 수 있는 해커가 설치한 악성 소프트웨어입니다.
  
Web Attack - Brute Force: 무차별 대입 공격(Brute Force)은 공격자가 사용자 이름 및 암호의 조합을 시도하여 시스템에 액세스하는 것을 목표로 합니다.
  
Web Attack - XSS: Cross-Site Scripting (XSS) 공격은 공격자가 웹 애플리케이션에 악성 스크립트를 삽입하여 사용자의 브라우저에서 실행되도록 하는 것을 목표로 합니다.
  
Infiltration: 시스템 또는 네트워크에 비인가적으로 접근하여 정보를 유출하려는 시도입니다.
  
Web Attack - Sql Injection: SQL Injection은 악의적인 SQL 문을 웹 애플리케이션의 입력 필드에 삽입하여 데이터베이스에 대한 액세스 권한을 부여하거나 데이터를 조작하는 공격입니다.
  
Heartbleed: OpenSSL의 Heartbeat 확장에 있는 버그를 이용하여 원격으로 시스템의 메모리를 읽는 공격입니다.
</pre>










![benign 결측값 제거](https://github.com/thejysplay/CIC-IDS-attack-detection/assets/101304095/fb470115-397c-41ad-a38d-516566250503)
![dos hulk 결측값제거](https://github.com/thejysplay/CIC-IDS-attack-detection/assets/101304095/43297baf-903a-443d-a4d0-c12a88271c28)
![데이터셋 총 컬럼 수](https://github.com/thejysplay/CIC-IDS-attack-detection/assets/101304095/311ca7ab-c5c2-42a3-87b6-062863018265)
![라벨 시각화](https://github.com/thejysplay/CIC-IDS-attack-detection/assets/101304095/9fbe9740-fc92-4729-8443-58e32107f334)
![라벨별 정확한 수치](https://github.com/thejysplay/CIC-IDS-attack-detection/assets/101304095/7887ef3b-9d3f-4255-867f-50c5d0d99cfc)
![총결측값제거 갯수](https://github.com/thejysplay/CIC-IDS-attack-detection/assets/101304095/b0b1c162-9323-4f5a-8a23-633c716b91d1)
![캡처](https://github.com/thejysplay/CIC-IDS-attack-detection/assets/101304095/08d1ca40-439e-4807-8dd0-125f64581334)
