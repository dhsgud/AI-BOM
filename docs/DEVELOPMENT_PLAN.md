# AI-BOM 개발 계획 (Development Plan)

본 문서는 AI-BOM 5단계 스캐닝 파이프라인의 개발 로드맵, 마일스톤,
기술 선택, 테스트 전략, 위험 요소를 정의한다.

---

## 1. 목표 & 범위

### 1.1 목표
- 신뢰할 수 없는 AI 모델 아티팩트를 **실행 없이** 정적/격리 분석
- 공급망 위협(악성 pickle, 변조 텐서, 백도어 트리거) 탐지
- 표준 **CycloneDX ML-BOM(JSON)** 산출 + `SAFE / WARNING / BLOCK` 판정
- 기존 `c4nary` 파서/리포터 자산을 재사용·확장

### 1.2 In Scope
- GGUF / GGML(`.bin`) / SafeTensors / PyTorch pickle(`.pt`, `.bin`, `.ckpt`) 포맷
- CLI 우선 (`aibom scan ...`), 라이브러리 API 제공
- Docker 기반 격리 로드 테스트

### 1.3 Out of Scope (초기)
- 실시간/스트리밍 스캔, 웹 UI, SaaS 배포
- 모델 정확도/성능 평가(보안 목적 외)
- GPU 필수 워크로드 (Stage 4는 선택·CPU 폴백)

---

## 2. 기술 스택

| 영역 | 선택 | 근거 |
|------|------|------|
| 언어 | **Python 3.11+** | picklescan·safetensors·cyclonedx-python-lib 생태계 |
| CLI | `typer` 또는 `click` | 서브커맨드·타입 검증 |
| 데이터 모델 | `pydantic` v2 | 단계 간 결과 스키마 검증 |
| Pickle 분석 | `picklescan` + 자체 opcode 워커 | 실행 없는 STACK_GLOBAL 탐지 |
| SafeTensors | `safetensors` + 자체 헤더 검증 | 헤더 무결성/오프셋 검증 |
| GGUF | 자체 파서(`c4nary`) | 렌더링/실행 없는 AST 추출 |
| 샌드박스 | Docker SDK for Python + seccomp 프로파일 | `--network none` 격리 |
| FS 모니터링 | `strace`(컨테이너 내) | 파일시스템 접근 탐지 |
| BOM | `cyclonedx-python-lib` (ML-BOM) | 표준 준수 |
| 행위 분석 | `torch` / `numpy` (선택 extra) | FGSM/PGD probe |
| 테스트 | `pytest`, `pytest-cov` | 단위·통합 |
| CI | GitHub Actions | lint(ruff) · type(mypy) · test |

> `pip install -e .` (core) / `.[sandbox]` / `.[behavioral]` 로 extra 분리하여
> 무거운 의존성(torch, docker)을 선택적으로 유지한다.

---

## 3. 아키텍처 개요

```
aibom/
├── cli.py            # 진입점: scan 서브커맨드, --until/--output 옵션
├── pipeline.py       # 단계 오케스트레이터 + 조기 종료(fail-fast) 로직
├── models.py         # StageResult / Finding / Verdict pydantic 스키마
├── verdict.py        # 단계별 findings → SAFE/WARNING/BLOCK 집계
└── stages/
    ├── stage1_c4nary.py     # GGUF AST + SHA-256 + remote 헤더 비교
    ├── stage2_format.py     # picklescan opcode + safetensors validator
    ├── stage3_sandbox.py    # Docker(--network none, seccomp) + strace
    ├── stage4_behavioral.py # FGSM/PGD probe + 트리거 키워드 + anomaly
    └── stage5_report.py     # CycloneDX ML-BOM 직렬화
```

**데이터 흐름:** 각 스테이지는 `StageResult`(findings 리스트 + 부분 BOM 조각)를
반환한다. `pipeline.py`가 이를 누적하고, 심각도에 따라 조기 종료(예: Stage 2에서
실행 페이로드 확정 시 BLOCK 후 Stage 3 스킵 옵션)를 결정한다.

---

## 4. 단계별 상세 설계

### Stage 1 — c4nary scan (GGUF 정적 분석)
- **입력:** 모델 파일 경로 / URL
- **동작:**
  - GGUF 매직/버전/메타데이터 KV를 파싱하여 **AST** 구축 (렌더링/실행 없음)
  - `template_ast`: chat_template 등 템플릿 필드를 파싱만 (Jinja 실행 금지)
  - SHA-256 계산 → 원격 카탈로그와 비교 (**HTTP HEAD/Range 헤더 fetch만 허용**)
- **탐지:** 매직 불일치, 비정상 KV, 원격 해시 불일치
- **non-GGUF 포맷은 통과시켜 Stage 2로 위임**

### Stage 2 — Format Scanner (pickle / safetensors)
- **picklescan 통합** + 자체 opcode 워커: `GLOBAL`, `STACK_GLOBAL`, `REDUCE`,
  `INST`, `OBJ`, `NEWOBJ` 등 실행 유발 opcode 탐지 (**unpickle 실행 금지**)
- 위험 import 알로리스트/블록리스트 (`os`, `subprocess`, `builtins.eval` 등)
- **safetensors validator:** 헤더 JSON 크기·오프셋·dtype 정합성, 텐서 영역 겹침 검사
- **탐지:** 임의 코드 실행 가능 opcode, 위험 콜러블 참조

### Stage 3 — Docker Sandbox (격리 로드 테스트)
- 최소 이미지에서 `--network none`, `--read-only`, seccomp 커스텀 프로파일,
  `--cap-drop ALL`, 메모리/CPU 제한으로 컨테이너 기동
- 모델을 **실제 로드만** 시도 (추론 없음) 하며 `strace`로 파일시스템·네트워크
  syscall 모니터링
- **탐지:** 예기치 않은 파일 쓰기, 네트워크 시도, 프로세스 생성

### Stage 4 — Behavioral Test (선택)
- FGSM/PGD 기반 adversarial probe로 입력 섭동에 대한 출력 일관성 측정
- c4nary로 추출한 **트리거 키워드** 후보를 주입하여 anomaly 스코어링
- CPU 폴백 지원, `--behavioral` 플래그로만 활성 (비용·시간 큼)

### Stage 5 — AI-BOM Report
- 모든 단계 findings + 아티팩트 메타데이터를 **CycloneDX ML-BOM(JSON)** 로 직렬화
- `c4nary report.py` 확장: components(모델/데이터셋), evidence, verdict 필드
- 최종 판정: 단계별 최고 심각도 → `SAFE / WARNING / BLOCK`

---

## 5. 마일스톤

| # | 마일스톤 | 범위 | 산출물 |
|---|----------|------|--------|
| **M0** | 스캐폴드 & CI | repo·패키지·CI·CLI 골격 | `aibom --help`, 통과하는 파이프라인 스텁 |
| **M1** | Stage 5 스켈레톤 | 빈 BOM 생성 + verdict 집계 | 유효한 CycloneDX JSON |
| **M2** | Stage 2 | picklescan + safetensors validator | pickle 악성 샘플 탐지 |
| **M3** | Stage 1 | GGUF 파서 + SHA-256 + remote 비교 | GGUF AST 리포트 |
| **M4** | Stage 3 | Docker 샌드박스 + strace | 격리 로드 리포트 |
| **M5** | Stage 4 | adversarial probe (선택) | anomaly 스코어 |
| **M6** | 통합 & 문서 | E2E 테스트·샘플 코퍼스·릴리스 | v0.1.0 태그 |

> **구현 순서 근거:** Stage 5→2 를 먼저 세워 "BOM 골격 + 확실한 위협 탐지"로
> 빠르게 가치를 내고, 무거운 Stage 1(파서)·3(Docker)·4(ML)를 뒤에 배치한다.

---

## 6. 테스트 전략
- **단위:** 각 스테이지 순수 로직 (opcode 파서, 헤더 검증, verdict 집계)
- **샘플 코퍼스:** `tests/fixtures/`에 양성/악성 모델 샘플 (악성은 무해한 마커 페이로드)
- **통합:** 파이프라인 E2E — 알려진 악성 샘플 → `BLOCK` 재현
- **보안 가드:** "실행 금지" 불변식 테스트 — 파서가 절대 unpickle/Jinja 렌더링
  하지 않음을 검증
- 커버리지 목표 80%+, CI에서 ruff + mypy + pytest 강제

---

## 7. 위험 요소 & 대응

| 위험 | 영향 | 대응 |
|------|------|------|
| 스캐너 자체가 악성 코드 실행 | 치명적 | 모든 파싱은 실행 없는 opcode/AST 수준, 불변식 테스트 |
| Docker 미가용 환경 | Stage 3 불가 | graceful skip + WARNING 명시 |
| torch 등 무거운 의존성 | 설치 부담 | extras로 분리, core는 경량 유지 |
| 원격 해시 비교 시 데이터 유출 | 프라이버시 | 헤더 fetch만, 해시만 전송, opt-out 플래그 |
| False positive 과다 | 신뢰도 저하 | 심각도 튜닝 · WARNING 계층 · 근거(evidence) 첨부 |

---

## 8. 다음 단계 (즉시 착수)
1. `M0` — 패키지 스캐폴드·CLI·CI 완성 (본 커밋에서 골격 제공)
2. `models.py` 스키마 확정 (`StageResult`, `Finding`, `Verdict`)
3. `M1` — Stage 5 CycloneDX 스켈레톤 + verdict 집계
4. 악성/양성 샘플 코퍼스 구축 시작
