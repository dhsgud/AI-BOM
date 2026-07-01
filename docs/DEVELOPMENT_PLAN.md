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
| Pickle 분석 | `picklescan` + 자체 opcode 워커 | 실행 없는 STACK_GLOBAL 탐지 (c4nary 미제공, **신규**) |
| SafeTensors | `safetensors` + 자체 헤더 검증 | 헤더 무결성/오프셋 검증 (c4nary 미제공, **신규**) |
| GGUF | **`c4nary` (외부 의존성, MIT)** | 렌더링/실행 없는 템플릿·메타·구조·토크나이저 룰. 재구현하지 않고 통합 |
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
    ├── stage1_c4nary.py     # c4nary 호출 → GGUF 템플릿/메타/구조/토크나이저 findings 매핑
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

### Stage 1 — c4nary scan (GGUF 정적 분석) — **c4nary 통합 (재구현 아님)**
> c4nary는 GGUF **전용** 감사기다. AI-BOM은 파서를 새로 만들지 않고 c4nary를
> 라이브러리/CLI(`canary scan --json`)/MCP로 호출해 findings를 매핑한다.
- **입력:** GGUF 파일 경로 (로컬) 또는 HuggingFace repo id/URL (`--remote`)
- **동작 (c4nary가 수행):**
  - GGUF 헤더 파싱 → 룰 실행: **템플릿(TPL)**·**메타데이터(MET)**·**토크나이저(TOK)**·
    **구조(STR)**·**무결성(INT)**. 절대 렌더링/실행 없음, jinja2는 AST 추출 용도만.
  - 핵심 차별점: **행위 백도어(silent-hijack) 정적 탐지** — content-키 분기,
    content-gated instruction injection, invisible/bidi 코드포인트 등 (TPL020-027)
  - `--remote`: HuggingFace **헤더만 range-fetch**(메타+템플릿+텐서맵), 가중치 미다운로드.
    이때 STR*·whole-file 무결성은 스킵됨.
  - SHA-256(파일/템플릿)은 **로컬 manifest drift 탐지**용 (원격 해시 카탈로그 비교 아님).
- **AI-BOM 매핑:** c4nary `FAIL/WARN/INFO` → AI-BOM `Severity`(아래 §9 매핑표)
- **non-GGUF 포맷은 통과시켜 Stage 2로 위임** (c4nary는 pickle/safetensors 미지원)

### Stage 2 — Format Scanner (pickle / safetensors) — **M2 완료**
- **picklescan 통합:** `scan_file_path`로 pickle global/opcode를 **unpickle 없이** 검사.
  `SafetyLevel.Dangerous`(os.system·eval 등)→`CRITICAL`, `Suspicious`→`MEDIUM`,
  `Innocuous`→무시. 규칙 id `pickle.<safety>-global`. scan_err→`HIGH`.
  torch zip(.pt)·raw pickle(.pkl/.bin/.ckpt/.pth) 모두 처리.
- **safetensors validator(자체 구현):** 헤더를 **바이트에서 직접 파싱**한다. 감사 대상
  로더로 파일을 로드하지 않기 위해 `safetensors` 라이브러리를 쓰지 않음. 검사 항목:
  헤더 길이 범위/오버사이즈(DoS), JSON 유효성, data_offsets 경계 초과, dtype·shape ↔
  바이트 span 정합성, 텐서 영역 겹침(aliasing). 구조 위반→`HIGH`, 오버사이즈 헤더→`MEDIUM`.
- **라우팅:** GGUF/미인식 포맷은 통과. **탐지 근거:** 임의 코드 실행 global, 크래프트된 헤더.
- E2E 검증: 악성 pickle(`os.system`)→**BLOCK**. 단위+통합 테스트 통과(총 21 테스트).

### Stage 3 — Docker Sandbox (격리 로드 테스트) — **M4 완료**
- **하드닝(`build_run_kwargs()`):** `network_mode=none` + `network_disabled`,
  `read_only` rootfs, `cap_drop=[ALL]`, `no-new-privileges`(+ 선택 seccomp),
  비-privileged, mem/pids/cpu 제한, 모델은 read-only 바인드, 쓰기는 `/tmp` tmpfs만.
- **probe 이미지(`sandbox/Dockerfile` + `probe.py`):** python:3.12-slim + strace,
  non-root(uid 10001). probe는 자신을 `strace`로 재실행해 모델을 **로드만**(추론 없음)
  시도하고, execve(프로세스 생성)·socket/connect(네트워크)·write-openat(파일쓰기)를
  파싱해 JSON 리포트를 stdout으로 낸다. pickle은 격리 안에서 실제로 detonate시켜 관찰.
  strace가 막히면 untraced 로드로 폴백(`traced:false`).
- **변환(`translate_probe_report()`):** 프로세스 생성→`CRITICAL`, 네트워크/파일쓰기
  →`HIGH`, oom/timeout/load-error→`MEDIUM`.
- **게이팅(`sandbox_available()`):** SDK 미설치/데몬 다운/이미지 부재 시 사유와 함께
  안전 skip → 보수적 WARNING.
- **라이브 검증(실 컨테이너):**
  - `os.system` pickle → `sandbox.process-spawn`(CRITICAL) + `sandbox.filesystem-write`(HIGH)
  - socket connect pickle → `sandbox.network-attempt`(HIGH, ENETUNREACH 로깅)
  - 양성 GGUF/safetensors → 무탐지 → **드디어 `SAFE` 판정 가능**(샌드박스 skip이 없어짐)
- **빌드:** `docker build -t aibom-sandbox:latest sandbox/`

### Stage 4 — Behavioral Test (선택, 연구성) — **주의: c4nary가 제공하지 않음**
> ⚠️ 이 단계는 유일하게 **모델을 실제 실행**한다. 따라서 반드시 **Stage 3 샌드박스
> 내부에서만** 수행하며, "절대 실행 금지" 원칙은 격리로 보장한다. c4nary는 가중치
> 실행을 **명시적으로 out-of-scope**로 규정하므로 이 단계의 로직은 전부 신규 개발이다.
- FGSM/PGD 기반 adversarial probe로 입력 섭동에 대한 출력 일관성/anomaly 측정
- **트리거 추출(결정: AI-BOM 자체 구현, c4nary 무수정):**
  - c4nary가 이미 공개하는 `parse_gguf`로 chat_template을 얻고, **Jinja AST를
    직접 순회**해 content-키 조건(`in` / `==` / `.startswith` / `.find`)의
    **리터럴 피연산자**를 트리거 후보로 추출한다 (예: `'deploy'`).
  - 이 추출기는 `aibom/stages/trigger_extract.py`로 분리. c4nary의 사람용 설명문
    (`detail`)을 문자열 파싱하는 방식은 취약하므로 **AST 재사용을 1순위**로 하고,
    AST 접근이 막히면 fallback으로만 사용한다.
  - probe: 각 트리거를 넣은 입력 vs 제거한 입력을 샌드박스 모델에 주고 출력 발산도로
    백도어 활성 여부를 스코어링.
- CPU 폴백 지원, `--behavioral` 플래그 + Docker 가용 시에만 활성 (비용·시간 큼)
- 미구현/미가용 시 `WARNING`이 아니라 단순 skip(INFO)으로 처리해 오탐 방지

### Stage 5 — AI-BOM Report — **M1 완료**
- 모든 단계 findings + 아티팩트 메타데이터를 **CycloneDX 1.6 ML-BOM(JSON)** 으로 직렬화
  (`cyclonedx-python-lib`, `build_bom()`).
- 스캔 대상 모델 = `metadata.component`(type `machine-learning-model`), Stage 1이 낸
  sha256/template_sha256는 컴포넌트 property로 첨부.
- 각 finding = `Vulnerability`(id=rule_id, `ratings[].severity` 매핑, `affects`→모델,
  `aibom:stage` property, evidence는 `detail` JSON). AI-BOM `Severity`→CycloneDX
  severity는 이름 1:1.
- 최종 판정 `SAFE/WARNING/BLOCK`는 `metadata` property `aibom:verdict`로 임베드.
  Stage 5가 `prior`로부터 verdict를 계산하므로 BOM이 자기완결적.
- **결정성:** 자동 생성되는 serial_number/timestamp를 제거해 동일 입력→동일 BOM
  (c4nary 결정성 불변식과 정렬).

---

## 5. 마일스톤

| # | 마일스톤 | 범위 | 산출물 |
|---|----------|------|--------|
| **M0** ✅ | 스캐폴드 & CI | repo·패키지·CI·CLI 골격 | `aibom --help`, 통과하는 파이프라인 스텁 |
| **M1** ✅ | Stage 5 | 실제 CycloneDX 1.6 ML-BOM 직렬화 (cyclonedx-python-lib) | 유효한 CycloneDX ML-BOM JSON |
| **M2** ✅ | Stage 2 | picklescan + safetensors 헤더 validator | pickle 악성/변조 safetensors 탐지 |
| **M3** ✅ | Stage 1 | **c4nary 통합** (Python API + Finding 매핑, severity 승격) | GGUF 룰 findings가 BOM에 반영 |
| **M4** ✅ | Stage 3 | 하드닝 컨테이너 + strace probe 이미지 + 라이브 검증 | 격리 로드 리포트 |
| **M5** | Stage 4 | 자체 트리거 추출기(`trigger_extract.py`) + adversarial probe (선택) | anomaly 스코어 |
| **M6** | 통합 & 문서 | E2E 테스트·샘플 코퍼스·릴리스 | v0.1.0 태그 |

> **구현 순서 근거:** Stage 5→2 를 먼저 세워 "BOM 골격 + 확실한 위협 탐지"로
> 빠르게 가치를 내고, 무거운 Stage 3(Docker)·4(ML)를 뒤에 배치한다. Stage 1은
> c4nary 통합(파서 신규개발 아님)이라 우선 완료했다.

**M3 완료 내역 (Stage 1):** `is_gguf` 매직 라우팅 → non-GGUF는 Stage 2로 통과.
GGUF는 c4nary Python API(`parse_gguf` + `analyze_template/metadata/tokenizer/
structure`) 호출 후 Finding을 매핑(FAIL→HIGH, SSTI/injection FAIL→CRITICAL,
WARN→MEDIUM, INFO→INFO; rule id는 `c4nary:<ID>` 보존). GGUF 매직인데 파싱 실패 시
`stage1.parse-error`(HIGH). E2E 검증: 악성 템플릿 GGUF→**BLOCK**, 양성→WARNING(현재
Stage 3 skip 때문). ruff/mypy(strict)/pytest 12개 통과.
- **남은 것:** `--remote`(HuggingFace 헤더 스캔) aibom CLI 연동, manifest drift(INT) 연동.

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

## 8. c4nary 통합 상세 (검증 완료: paraxaQQ/canary)

### 9.1 c4nary 실측 사실
- **범위:** GGUF **전용**. pickle·safetensors·가중치 값은 다루지 않음(명시적 out-of-scope)
- **의존성:** `jinja2` 하나(AST 추출 전용, 렌더링 금지). Python 3.10+, **MIT 라이선스**
- **인터페이스:** ① Python API(`parse_gguf`, `analyze_template/metadata/tokenizer/structure`,
  `compare_manifest`) ② CLI `canary scan --json` ③ MCP 서버(`c4nary-mcp`)
- **룰 패밀리:** `TPL`(템플릿 SSTI+행위백도어), `STR`(구조), `MET`(메타), `TOK`(토크나이저),
  `INT`(무결성). 각 finding = `(rule_id, severity, title, detail, location)`
- **severity:** `FAIL / WARN / INFO`. 종료코드 0/1(warn)/2(fail)/>2(error)
- **불변식:** 렌더링·실행 금지, 코어 오프라인, 읽기 전용, 결정적(byte-identical), 설명가능

### 9.2 통합 방식
- **채택:** c4nary를 **의존성으로 추가**(`pip install c4nary[remote]`)하고 Python API 우선 호출,
  격리가 필요하면 `canary scan --json` 서브프로세스. GGUF 파서를 재구현하지 않음.
- **버전 고정:** `c4nary>=0.1,<0.2` (룰 id/JSON 스키마 안정성 확보 전까지 상한 고정)

### 9.3 severity 매핑 (c4nary → AI-BOM)
| c4nary | AI-BOM `Severity` | 근거 |
|--------|-------------------|------|
| `FAIL` | `HIGH` (SSTI/injection 계열은 `CRITICAL`) | 확정적 위험 구성물 → BLOCK |
| `WARN` | `MEDIUM` 또는 `LOW` | 휴리스틱 리뷰 프롬프트 → WARNING |
| `INFO` | `INFO` | 정보성 |
> c4nary rule_id는 `bom.rule_id` 네임스페이스에 `c4nary:TPL021` 형태로 보존한다.

### 9.4 라이선스 정합성
- c4nary=MIT, AI-BOM=Apache-2.0. MIT 의존성을 Apache-2.0 프로젝트에서 사용하는 것은 호환.
  코드 **벤더링 시** c4nary MIT 고지 유지 필요. 기본은 pip 의존성으로만 사용.

## 9. 다음 단계 (즉시 착수)
1. `M0` — 패키지 스캐폴드·CLI·CI 완성 (본 커밋에서 골격 제공)
2. `models.py` 스키마 확정 (`StageResult`, `Finding`, `Verdict`) + c4nary severity 매핑 유틸
3. `M1` — Stage 5 CycloneDX 스켈레톤 + verdict 집계
4. `M3`(Stage 1)을 우선순위 상향 검토 — c4nary 통합은 파서 신규개발이 아니라
   의존성 연동이므로 M2(pickle)보다 빠르게 가치 실현 가능
5. 악성/양성 샘플 코퍼스 구축 시작 (c4nary `tests/fixtures/*.jinja` 참고)
