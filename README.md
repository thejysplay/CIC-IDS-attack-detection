# CIC-IDS-attack-detection
AI프레임워크 보안 1주차 수행과제
해당 데이터 셋은 https://www.unb.ca/cic/datasets/ids-2017.html

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











![benign 결측값 제거](https://github.com/thejysplay/CIC-IDS-attack-detection/assets/101304095/fb470115-397c-41ad-a38d-516566250503)
![dos hulk 결측값제거](https://github.com/thejysplay/CIC-IDS-attack-detection/assets/101304095/43297baf-903a-443d-a4d0-c12a88271c28)
![데이터셋 총 컬럼 수](https://github.com/thejysplay/CIC-IDS-attack-detection/assets/101304095/311ca7ab-c5c2-42a3-87b6-062863018265)
![라벨 시각화](https://github.com/thejysplay/CIC-IDS-attack-detection/assets/101304095/9fbe9740-fc92-4729-8443-58e32107f334)
![라벨별 정확한 수치](https://github.com/thejysplay/CIC-IDS-attack-detection/assets/101304095/7887ef3b-9d3f-4255-867f-50c5d0d99cfc)
![총결측값제거 갯수](https://github.com/thejysplay/CIC-IDS-attack-detection/assets/101304095/b0b1c162-9323-4f5a-8a23-633c716b91d1)
![캡처](https://github.com/thejysplay/CIC-IDS-attack-detection/assets/101304095/08d1ca40-439e-4807-8dd0-125f64581334)
