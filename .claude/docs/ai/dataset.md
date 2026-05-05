# 데이터셋 · 실험 결과 (AI/ML 담당)

> 담당: 영현 / 브랜치: `feat/ai/dataset`

## Case별 학습 데이터 구성 (A~F)

| Case | Normal | 주요 변경 | CSIC DR | CSIC FPR | OOD FPR |
|------|--------|---------|---------|---------|---------|
| A | SecLists 합성 | 합성 데이터만 | 7.92% | 0%* | — |
| B | CSIC2010 | CSIC 공격만 | 97.23% | 1.74% | — |
| C | CSIC2010 | SecLists+CSIC 혼합 | 96.42% | 0.54% | 100% |
| D | CSIC2010 + 합성 118건 | HttpParams 보강 | 94.97% | 0.13% | 87.82% |
| E | CSIC2010 + 합성 149건 | NFKD 정규화, max_length=256 | 96.99% | 0.00% | 88.20% |
| **F** | **CSIC2010 + 합성 144건 + VulnBank 1,000건** | **VulnBank benign 학습 투입** | **97.28%** | **0.27%** | **0.14%** |

> *Case A FPR 0%는 거의 모두 Normal 예측으로 인한 무의미한 수치

## 채택 모델: Case F 데이터 구성

| Split | Normal | SQLi | XSS | CMDi | Path | 합계 |
|-------|--------|------|-----|------|------|------|
| Train | 4,569 | 6,000 | 3,343 | 3,000 | 3,053 | **19,965** |
| Val | 923 | 1,242 | 756 | 642 | 649 | 4,212 |
| Test | 747 | 1,622 | 96 | 0 | 12 | 2,477 |

Normal 4,569 = CSIC2010 3,420 + 합성 144건 + VulnBank benign 1,000건 (merge 중복 제거 5건 포함)

**데이터 소스**
- `CSIC2010`: `/home/gyh3257/waf_model/data/csic_normal.txt`, `csic_attack.txt`
- `SecLists/PayloadsAllTheThings`: `/home/gyh3257/waf_model/data/raw/{sqli,xss,cmdi,path}.txt`
- `VulnBank OOD`: `/home/gyh3257/waf_model/data/ood_vulnbank/` (test.csv 전체, eval.csv held-out)

## 성능 지표 (Case F 기준)

| 지표 | CSIC2010 | VulnBank OOD (held-out) |
|------|---------|----------------------|
| Detection Rate | **97.28%** | 91.65% |
| False Positive Rate | 0.27% | **0.14%** |
| Precision | 99.88% | **99.66%** |
| F1-Attack / F1-binary | **98.57%** | **95.48%** |
| ROC-AUC | 0.9953 | **0.9992** |

## 미탐(FN) 분석

**CSIC2010**: 47건 = 등록 폼(`registro.jsp`, `editar.jsp`)의 약한 특수문자 패턴 (256자 초과 URL 93%)  
**VulnBank OOD**: 79건 = 정상 API 구조에 악의적 파라미터 값 삽입 (음수 금액 송금, 권한 탈취 등)  
→ 로직 기반 공격은 텍스트 패턴만으로 탐지 한계 존재. 지속 학습 파이프라인 필요성의 근거.
