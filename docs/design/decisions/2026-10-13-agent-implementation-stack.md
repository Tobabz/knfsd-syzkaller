# 결정 기록: Agent pipeline 구현 스택과 착수 순서 (2026-10-13)

> 종류: 결정 기록 (임시 문서)   ·   승인: 사용자, 2026-10-13   ·   관련 설계: `02-llm-agent/01` §10, §11, §14

## 삭제 조건

이 문서는 Agent pipeline 구현 설계가 내용을 흡수할 때까지 결정과 근거를 보존하기 위한 임시 기록이다. 아래가 **모두** 충족되면 삭제한다.

1. Controller와 Agent Task 구현을 다루는 설계 문서가 `docs/design/02-llm-agent/`에 있고 `상태: reviewed` 이상이다.
2. 그 문서에 아래 "결정", "검토한 대안", "남은 위험"의 내용이 반영되어 있다(요약이어도 출처가 있으면 된다).
3. `pyproject.toml`과 `uv.lock`이 결정 2의 패키지를 정확한 버전으로 고정한다.

삭제할 때는 삭제 커밋 메시지에 흡수한 문서 경로를 적는다.

## 문제

- `02-llm-agent/01`은 Agent pipeline의 데이터 계약, 판정 규칙, 신뢰 경계를 고정했지만 구현 수단은 정하지 않았다.
  §14의 12번(repair/state graph)과 13번(Agent SDK 선택과 agent/tool 정의)이 비어 있었다.
- Controller의 언어, job 상태 저장소, 착수 순서는 어느 문서에도 없었다.
- 이 상태로 구현을 시작하면 첫 PR이 프레임워크와 저장소를 암묵적으로 정하고, Controller의 상태 기계를 코드에서
  즉흥으로 정해 설계 문서와 어긋난다.

## 결정

1. **착수 순서: Stage 1 먼저.** Controller intake와 harness binding, Candidate Analysis, Reachability Planning,
   Harness Materializer, Q1 Judge를 먼저 만들고 Proxy M2–M7과 병행한다. Stage 2(Mutation Strategy, Mutation Rule
   Compiler, M1 Judge, campaign)는 Proxy M4 이후에 시작한다.
   - 근거: Stage 2의 Agent는 M7 promotion을 통과한 semantic subset만 쓸 수 있고(`02-llm-agent/08` §14, `04` §5),
     Compiler는 ProtocolSchema와 promoted registry를 입력으로 쓴다(`08` §12). M7 전에 만든 Stage 2는 실행할 대상이
     없다. Stage 1은 이미 있는 HCAP-01–06만 쓴다(`04` §5).
   - Q2 Judge는 Proxy milestone과 별개의 acceptance gate를 가지므로(`01` §14 11번) Stage 1과 함께 만들 수 있다.

2. **Agent 프레임워크: PydanticAI** (`pydantic-ai-slim`과 쓰는 provider의 extra).
   - 원칙(사용자 결정): 특별히 필요한 기능이 없는 한 여러 provider를 쓸 수 있는 프레임워크를 쓴다.
   - 설계가 Agent에 요구하는 것은 구조화 출력, read-only tool, specialist 분리, shell 권한 없음(`01` §10)이다.
     어느 것도 특정 provider의 기능이 아니므로 단일 provider SDK를 쓸 이유가 없다.
   - Agent Task의 출력 schema는 데이터 계약(`02`–`08`)을 Pydantic model로 옮긴 것이고, Controller는 같은 model로
     출력을 검증한다. provider를 바꿔도 schema와 검증은 그대로다.
   - Agent에는 read-only tool만 등록한다(kernel source 읽기와 검색, caller/callee 조회, HCAP 조회, 봉인 evidence
     읽기). shell, 파일 쓰기, 네트워크 tool은 등록하지 않는다. tool 목록과 정의는 첫 Stage 1 구현에서 정한다
     (`01` §14 13번의 나머지).
   - 설계 문서의 "Agent SDK"는 특정 제품이 아니라 reasoning runtime을 가리키는 일반 용어로 남긴다.

3. **Controller: Python. job 상태는 SQLite, artifact는 SHA-256 content-addressed 디렉터리. workflow 엔진은 쓰지
   않는다.**
   - 근거: 저장소 도구가 이미 Python과 uv로 관리된다(`pyproject.toml`, `uv.lock`, `.python-version`은 3.12).
     Judge는 "봉인 bundle + profile -> verdict" 순수 함수이고(`01` §11.1) artifact는 SHA-256으로 대조하므로 파일
     기반 content-addressed 저장이 맞다. stage 전이와 repair budget은 Controller가 소유하므로(`01` §11) 외부
     workflow 엔진이나 agent 프레임워크의 graph 기능에 넘기지 않는다.
   - PydanticAI 2.x는 Python 3.11 이상을 요구한다. 첫 구현 PR에서 `requires-python`을 `>=3.11`로 올린다.
     그대로 두면 uv가 Python 3.10을 지원하는 이전 major로 해석할 수 있다(미검증, uv resolver 동작에서 추론).

4. **repair/state graph를 코드보다 먼저 고정한다.** job 상태, 전이, budget, 재시작 규칙은
   `02-llm-agent/09-job-state-graph.md`가 소유한다.

5. **model/provider는 Agent Task별 설정값이다.** 코드에 고정하지 않는다. model/provider는 trusted controller의
   execution policy이며(`02` §8) JobPolicy와 함께 기록하고, 실행마다 실제로 응답한 model id를 Agent 실행 기록에
   남긴다(`09-job-state-graph.md` §8). 기본 모델은 첫 Stage 1 구현에서 정한다.
   - model id는 ExecutionHarnessIdentity에 넣지 않는다. Agent 출력은 Materializer와 Compiler가 검증하는
     제안이며 관측을 만드는 계측이 아니다(`01` §11.2).

## 검토한 대안

| 안 | 얻는 것 | 비용·한계 | 채택 여부와 이유 |
|---|---|---|---|
| Claude Agent SDK | 파일·검색 tool, subagent, context 관리가 기본 제공 | Anthropic 모델 전용 | 채택 안 함. 여러 provider 원칙에 어긋난다. 기본 tool은 어차피 read-only로 다시 정의해야 한다 |
| OpenAI Agents SDK | handoff, tracing | 다른 provider는 extra(`litellm`, `any-llm`)로 쓴다. 2026-10-13 기준 0.x(0.23.1) | 채택 안 함. 1.0 이후 다른 provider가 기본 경로가 되면 재검토 |
| Strands Agents | 여러 provider(extra로 확인), 구조화 출력 | PydanticAI 대비 계약 중심 기능의 이점을 찾지 못했다 | 차선. PydanticAI의 provider 지원이나 유지보수가 끊기면 재검토 |
| LangGraph | durable graph, checkpoint | graph 실행 엔진이 Controller가 소유하는 stage 전이와 repair 경로와 겹친다 | 채택 안 함. Controller 상태 기계를 직접 유지하는 비용이 커지면 재검토 |
| Google ADK | Gemini 통합 | Gemini 밖의 모델은 extra(`openai`)나 adapter로 쓴다 | 채택 안 함 |
| smolagents | 가볍다 | 모델이 쓴 Python 코드를 실행하는 CodeAgent가 기본 형태. "Agent는 shell 권한 없음"(`01` §10)과 어긋난다 | 채택 안 함 |
| LiteLLM + 직접 작성한 loop | provider 범위가 가장 넓고 의존성이 작다 | tool loop, 출력 검증 재시도, 구조화 출력을 직접 소유한다 | 채택 안 함. PydanticAI가 막는 기능이 생기면 재검토 |
| Controller를 Temporal 같은 workflow 엔진 위에 | 재시작·재시도 내장 | 운영 구성요소가 늘고 단일 호스트 도구에 과하다 | 채택 안 함. Runner를 여러 호스트에 분산할 때 재검토 |
| job 상태를 JSON 파일로만 | 의존성 없음 | 전이의 원자성과 동시 갱신을 직접 구현해야 한다 | 채택 안 함. SQLite는 Python 표준 라이브러리에 있다 |

## 확인한 사실 (2026-10-13)

PyPI metadata로 확인했다. 공식 문서 사이트(`pydantic.dev`)는 이 작업 환경의 network policy로 열리지 않아, 기능
설명은 PyPI의 패키지 설명과 wheel의 모듈 목록을 기준으로 한다.

| 패키지 | 최신 버전 (업로드 날짜) | 확인한 내용 |
|---|---|---|
| `pydantic-ai-slim` | 2.55.0 (2026-10-09) | MIT, `Requires-Python: >=3.11`. 2.0.0은 2026-06-23. wheel의 `pydantic_ai/models/`에 `anthropic`, `openai`, `google`, `bedrock`, `mistral`, `groq`, `cohere`, `ollama`, `xai`, `openrouter`, `fallback`, `function`, `test` 모듈이 있다. `pydantic_ai/providers/`에 `litellm`, `vllm`, `azure`, `deepseek`, `together` 등이 있다. `NativeOutput`, `ToolOutput`, `PromptedOutput`, `UsageLimits`를 export한다 |
| `pydantic-ai-harness` | 0.55.0 (2026-10-09) | 별도 패키지. sub-agent, context 관리(compaction), file·shell capability를 제공한다(`pydantic-ai` 패키지 설명 기준, 미검증) |
| `openai-agents` | 0.23.1 (2026-10-02) | extra `litellm`, `any-llm` |
| `strands-agents` | 1.60.0 (2026-10-12) | extra `anthropic`, `openai`, `gemini`, `mistral`, `ollama`, `litellm` 등 |
| `langgraph` | 1.2.15 (2026-10-12) | — |
| `google-adk` | 2.11.0 (2026-10-02) | extra `openai` |
| `smolagents` | 1.26.0 (2026-05-29) | extra `litellm`, `openai` 등 |
| `litellm` | 1.105.0 (2026-10-11) | — |
| `claude-agent-sdk` | 0.2.165 (2026-10-08) | — |

## 남은 위험

- PydanticAI는 릴리스가 잦다(2.0.0 2026-06-23, 2.55.0 2026-10-09). `uv.lock`에 정확한 버전을 고정하고, 올릴 때는
  Agent Task 테스트를 다시 돌린다.
- provider마다 tool 호출과 구조화 출력의 품질이 다르다. 출력은 Controller가 schema로 검증하므로 잘못된 출력이
  판정을 바꾸지는 않지만, repair 횟수와 비용은 모델에 따라 달라진다. 모델 비교는 기록된 model id로 한다.
- `TestModel`/`FunctionModel`로 LLM 호출 없이 결정적 테스트를 한다는 계획은 모듈 존재만 확인했다(미검증).
  첫 구현에서 확인한다.
- read-only 경계는 tool 등록으로만 강제된다. `pydantic-ai-harness`의 file·shell capability처럼 쓰기나 실행 권한을
  주는 확장은 Agent Task에 붙이지 않는다.
