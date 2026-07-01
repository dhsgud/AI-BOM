# AI-BOM

> **AI Model Security Scanner & ML-BOM Generator**
> AI 모델 파일(GGUF / Pickle / SafeTensors)을 **실행 없이** 정적·격리 분석하여
> 공급망 위협을 탐지하고 [CycloneDX](https://cyclonedx.org/) ML-BOM 리포트를 생성합니다.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Status](https://img.shields.io/badge/status-alpha-orange.svg)

---

## 개요

`model.gguf` / `model.bin` / `model.safetensors` 같은 배포 모델 아티팩트에는
악성 pickle 페이로드, 변조된 텐서, 백도어 트리거 등이 숨어 있을 수 있습니다.
**AI-BOM**은 이러한 아티팩트를 **5단계 파이프라인**으로 검사하고,
최종적으로 `SAFE / WARNING / BLOCK` 판정과 함께 표준 ML-BOM(JSON)을 산출합니다.

핵심 원칙: **"절대 신뢰하지 않는 모델을 절대 그냥 실행하지 않는다."**
정적 분석 → 포맷 검증 → 네트워크 격리 샌드박스 → (선택) 행위 분석 순으로
위험도를 점진적으로 확정합니다.

## 파이프라인

```
model.gguf / model.bin / model.safetensors
         │
         ▼
  Stage 1  c4nary scan        GGUF 템플릿 백도어/SSTI·메타·구조·토크나이저 정적 룰 (c4nary 통합)
         │ (non-GGUF)
         ▼
  Stage 2  Format Scanner     picklescan opcode 분석 · safetensors 검증 · 실행코드 탐지 (신규)
         │
         ▼
  Stage 3  Docker Sandbox     --network none + seccomp · 격리 로드 · strace FS 모니터링
         │ (선택적)
         ▼
  Stage 4  Behavioral Test    (샌드박스 내) FGSM/PGD adversarial probe · anomaly 스코어 (신규)
         │
         ▼
  Stage 5  AI-BOM Report      CycloneDX ML-BOM JSON · SAFE / WARNING / BLOCK
```

> Stage 1은 GGUF 전용 정적 감사기 [`c4nary`](https://github.com/paraxaQQ/canary)를
> 통합합니다(파서 재구현 아님). Stage 2(pickle/safetensors)와 Stage 4(가중치 행위
> 분석)는 c4nary 범위 밖이라 신규 개발합니다. Stage 4는 유일하게 모델을 실행하므로
> **반드시 Stage 3 샌드박스 안에서만** 동작합니다.

각 단계의 상세 설계는 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md),
개발 일정·마일스톤은 [docs/DEVELOPMENT_PLAN.md](docs/DEVELOPMENT_PLAN.md)를 참조하세요.

## 빠른 시작 (예정)

```bash
# 설치 (개발 모드)
pip install -e .

# 단일 모델 스캔
aibom scan ./model.gguf

# 특정 단계까지만 실행 + BOM 출력
aibom scan ./model.safetensors --until stage3 --output bom.json
```

> ⚠️ **알파 단계** — 현재 아키텍처/스캐폴드만 구현되어 있습니다.
> 실행 가능한 기능은 [개발 계획](docs/DEVELOPMENT_PLAN.md)의 마일스톤에 따라 추가됩니다.

## 판정 기준

| 판정 | 의미 |
|------|------|
| `SAFE` | 알려진 위협 미탐지, 모든 무결성 검증 통과 |
| `WARNING` | 의심 신호 존재(미확인 opcode, 원격 해시 불일치 등) — 사람 검토 권장 |
| `BLOCK` | 실행 가능 페이로드·악성 트리거 등 명확한 위협 — 사용 차단 |

## 저작권 고지 (Attribution)

AI-BOM의 **Stage 1**은 GGUF 정적 감사기
[**c4nary**](https://github.com/paraxaQQ/canary) (© 2026 Actual Intelligence LLC,
**MIT**)을 사용합니다. 전체 라이선스 원문과 서드파티 고지는
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)를 참조하세요.

## 라이선스

[Apache License 2.0](LICENSE) — 단, 번들/의존하는 서드파티 구성요소는 각자의
라이선스를 따릅니다([THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)).
