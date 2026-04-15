# Post-MVP 로드맵

> MVP 범위 밖으로 명시적으로 제외된 항목들.
> 구현 완료 후 우선순위에 따라 순차 적용 예정.

---

## 1. 지속 학습 파이프라인

**배경**

논문 실험(4.4절)에서 62건의 미탐(FN)이 발생했으며, 이는 명시적 공격 키워드가 없는
파라미터 변조형 공격이 원인. 현재 모델은 정적 가중치로 배포되므로 새로운 변형 공격
패턴에 대한 적응력이 없음.

**설계 방향**

```
Attack Log (BLOCK / MONITOR)
        ↓
미탐 후보 수집 (FN 추정 샘플: MONITOR 중 운영자 확인)
        ↓
라벨링 파이프라인 (반자동 키워드 매칭 + 운영자 검토)
        ↓
증분 Fine-tuning (DistilBERT, 주기적 재학습)
        ↓
모델 성능 비교 (DR / FPR 기준) → 기준 통과 시 FastAPI 서버 교체
```

**주요 고려사항**

- 재학습 주기: 미탐 누적량 기준 트리거 vs 주기적 스케줄 (미정)
- 학습 데이터 관리: TimescaleDB의 공격 로그를 학습 소스로 재활용
- 모델 버전 관리: HuggingFace Hub 또는 로컬 모델 레지스트리
- 데이터셋 전략은 영현(AI/ML) 담당 → [.claude/docs/ai/dataset.md](.claude/docs/ai/dataset.md) 참고

---

## 2. RabbitMQ 적용

**배경**

MVP에서는 `@Async` + `@TransactionalEventListener` 조합으로 비동기 처리를 구현했으나,
트래픽이 급증하거나 Feedback Bridge 처리가 지연될 경우 스레드 풀 포화 가능성이 있음.
RabbitMQ는 이를 메시지 큐로 분리하여 배압(backpressure) 제어와 재처리를 보장함.

**설계 방향**

```
AttackLogService (Spring)
        ↓ publish
[Topic Exchange: waf.exchange]
        ├──▶ attack-log-queue       → 로그 영속화
        └──▶ feedback-queue         → Feedback Bridge 트리거
                                            ↓ (실패 시)
                                      [Dead Letter Queue]
                                            ↓ 재처리 또는 알림
```

**Exchange / Queue 구성**

| Queue | Routing Key | Consumer | 비고 |
|-------|-------------|----------|------|
| `attack-log-queue` | `waf.attack.detected` | AttackLogService | 영속화 |
| `feedback-queue` | `waf.attack.detected` | FeedbackBridgeService | Semgrep 분석 |
| `feedback-dlq` | DLX 자동 라우팅 | 알림 / 수동 재처리 | 실패 메시지 보관 |

**주요 고려사항**

- MVP의 `@TransactionalEventListener` 구조를 유지한 채 Publisher 부분만 RabbitMQ로 교체 가능
- Quorum Queue 적용 시 Raft 기반 복제로 메시지 유실 방지
- Consumer 재시도 전략: `spring.rabbitmq.listener.simple.retry` + DLQ 조합
- 도입 시 Docker Compose에 RabbitMQ 서비스 추가 필요

---

## 우선순위 기준

두 항목 모두 MVP 안정화 이후 적용. 순서는 운영 중 발생하는 미탐 빈도와
트래픽 규모에 따라 결정.

| 항목 | 선행 조건 |
|------|-----------|
| 지속 학습 파이프라인 | MVP 운영 후 FN 샘플 수집, 영현 모델 재학습 환경 준비 |
| RabbitMQ 적용 | MVP 안정화, Feedback Bridge 처리 지연 문제 확인 시 |
