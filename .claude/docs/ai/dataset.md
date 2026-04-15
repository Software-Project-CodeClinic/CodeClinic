# 데이터셋 · 실험 결과 (AI/ML 담당)

> 담당: 영현 / 브랜치: `feat/ai/dataset`

## 3-Case 학습 데이터 구성

| Case | Normal | Attack (Labeled) | Attack (Unlabeled) | Total |
|------|--------|------------------|--------------------|-------|
| A | CSIC2010 normal | SecLists | - | 15,414 |
| B | CSIC2010 normal | - | CSIC2010 attack | 9,791 |
| C | CSIC2010 normal | SecLists | CSIC2010 attack | 18,816 |

- CSIC2010 attack: 키워드 매칭 기반 자동 분류 → 라벨 노이즈 포함
- **채택: Case C** — FPR 0.54% (Case B 대비 3배 감소), Macro F1 0.979

## 성능 지표 (Case C 기준)

| 지표 | 값 |
|------|----|
| Detection Rate (DR) | 96.42% |
| False Positive Rate (FPR) | 0.54% |
| False Negative Rate (FNR) | 3.58% |
| Macro F1 | 0.979 |
| ROC-AUC | 0.994 |

## 미탐(FN) 분석

62건 미탐 = 명시적 공격 키워드 없는 **파라미터 변조형** 공격.  
→ 지속 학습 파이프라인 필요성의 근거 (논문 5절 future work)
