# Sawone Red

Sawone Red is an offensive security testing tool for AI/ML systems: LLM chatbots,
AI agents, agentic workflows, AI APIs and AI-powered application endpoints. It
finds vulnerabilities before attackers do, writes professional reports, and
gates CI pipelines on the results.

Copyright (c) 2026 Sawan Bhan. All rights reserved. Licensed under the MIT License.

## Responsible use

Use Sawone Red only against systems you own or are explicitly authorized to
test. The tool enforces this:

- Any real target requires an `authorization` block with `authorized: true`
  (the YAML boolean), a non-blank `owner` and a non-blank `scope`. Otherwise the
  run is refused before any request is sent.
- The built-in mock is self-contained and exempt.
- Probes never need harmful content. They plant a canary token in the target's
  system prompt and check whether it leaks, or inject a benign marker and check
  whether the target echoes it. A finding means a control failed.

## Features

- Probe library in YAML covering OWASP LLM Top 10 categories LLM01, LLM02,
  LLM05 and LLM06, jailbreak framings, PII handling, and agentic tool abuse.
- Lethal-trifecta check: flags agents that combine private data access,
  untrusted input and an outbound channel.
- Three target adapters: built-in mock, OpenAI-compatible APIs (OpenAI, Azure
  OpenAI, vLLM, Ollama), and generic JSON HTTP endpoints.
- Reports: self-contained HTML, JSON, Markdown, and SARIF 2.1.0 for GitHub code
  scanning. Each report includes a risk score and OWASP coverage.
- Deterministic runs when a seed is pinned, so CI results are reproducible.
- Pure Python standard library for the engine. The only dependency is PyYAML.
  No third-party red-team framework is used.

## Quick start

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[test]"
.venv/bin/sawone-red validate --config examples/mock.yaml
.venv/bin/sawone-red run --config examples/mock.yaml
.venv/bin/sawone-red run --config examples/mock-hardened.yaml
```

The vulnerable mock exits with code 1 and reports 22 findings. The hardened mock
exits with code 0 and reports none. No API keys are needed.

## CLI

| Command | Purpose |
| --- | --- |
| `sawone-red run --config FILE [--fail-on SEVERITY] [--output-dir DIR] [--sarif PATH]` | Run probes, write reports, gate on severity |
| `sawone-red validate [--config FILE]` | Check the probe library and optionally a config |
| `sawone-red list-packs` | List probe packs, OWASP categories and probe counts |

Exit codes: `0` passed, `1` findings at or above `--fail-on`, `2` configuration
or authorization error, `3` no probe reached the target.

## GitHub Action

```yaml
- uses: actions/checkout@v4
- uses: hackin2minutes-oss/sawone-red@v1
  with:
    config: examples/mock-hardened.yaml
    fail_on: high
    sarif_output: sawone-red.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: sawone-red.sarif
```

Inputs: `config`, `fail_on`, `sarif_output`, `report_dir`. The workflow in
`.github/workflows/sawone-red-example.yml` shows the full pattern.

## Project layout

```
sawone_red/             engine package
  adapters/             mock, openai_compat, http_generic
  data/probes/          YAML probe library (edit to add probes)
  config.py             config loading and the authorization gate
  detectors.py          canary_leak, marker_echo, contains_any, refused, regex
  probes.py             pack loading and validation
  runner.py             executes probes and scores results
  report.py             HTML report
  outputs.py            JSON, Markdown, SARIF
  cli.py                sawone-red command
examples/               mock, hardened mock, OpenAI-compatible and HTTP templates
tests/                  pytest suite
action.yml, Dockerfile, entrypoint.sh   GitHub Action
```

See [PLAYBOOK.md](PLAYBOOK.md) for configuration, writing probes, reading
reports and operating the Action.

## Development

```bash
.venv/bin/pytest -q
```

The suite covers the authorization gate, every detector, probe validation, both
mock modes, report outputs, the CLI, and repository policy (ownership headers
and plain ASCII text).

## License

MIT. See [LICENSE](LICENSE).
