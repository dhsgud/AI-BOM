# AI-BOM 아키텍처

## 설계 원칙

1. **Never execute untrusted models** — 모든 분석은 실행 없는 정적 파싱 또는
   완전 격리된 샌드박스에서만 수행한다. 파서는 unpickle, `eval`, Jinja 템플릿
   렌더링을 절대 하지 않는다.
2. **Fail toward safety** — 판정이 모호하면 `SAFE`가 아니라 `WARNING`으로 기운다.
3. **Progressive disclosure of risk** — 값싼 정적 검사(Stage 1–2)를 먼저, 비싼
   격리/행위 검사(Stage 3–4)를 뒤에 두어 조기 종료로 비용을 절감한다.
4. **Standards-first output** — 결과는 항상 CycloneDX ML-BOM으로 표현되어
   다른 공급망 보안 도구와 상호운용된다.

## 컴포넌트 다이어그램

```
        ┌──────────┐
  CLI ─►│ Pipeline │─► StageResult 누적 ─► Verdict 집계 ─► ML-BOM
        └────┬─────┘
             │ 순차 실행(조기 종료 가능)
   ┌─────────┼─────────┬─────────┬─────────┐
   ▼         ▼         ▼         ▼         ▼
 Stage1    Stage2    Stage3    Stage4    Stage5
 c4nary    Format    Sandbox   Behavior  Report
```

## 핵심 데이터 모델 (초안)

```python
class Severity(Enum):        # INFO < LOW < MEDIUM < HIGH < CRITICAL
    ...

class Finding(BaseModel):
    stage: str
    severity: Severity
    rule_id: str
    message: str
    evidence: dict           # opcode 위치, 오프셋, syscall 로그 등

class StageResult(BaseModel):
    stage: str
    ok: bool                 # 스테이지 실행 성공 여부(탐지 유무 아님)
    findings: list[Finding]
    bom_fragment: dict | None

class Verdict(Enum):
    SAFE = "SAFE"
    WARNING = "WARNING"
    BLOCK = "BLOCK"
```

## 판정 집계 규칙 (초안)

| 조건 | 판정 |
|------|------|
| CRITICAL 또는 HIGH finding 존재 | `BLOCK` |
| MEDIUM/LOW finding 존재, 또는 스테이지 skip(예: Docker 미가용) | `WARNING` |
| 모든 스테이지 통과, finding 없음 | `SAFE` |

## 확장 포인트
- **새 포맷:** `stages/` 에 validator 추가 후 `pipeline.py` 라우팅 등록
- **새 규칙:** `Finding.rule_id` 네임스페이스로 규칙 카탈로그 관리
- **BOM 소비자:** Stage 5의 CycloneDX 출력은 스키마 고정 → CI/게이트에 연동
