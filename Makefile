PY ?= python

.PHONY: install test lint data eval judge registry results demo

install:
	$(PY) -m pip install -e ".[dev]"

test:
	$(PY) -m pytest -q

lint:
	ruff check .

data:            ## rebuild data/mcptox.jsonl from the pinned MCPTox commit
	$(PY) eval/build_mcptox.py

eval:            ## static rules + keyword baseline on dev and test (seconds)
	$(PY) eval/run_eval.py

judge:           ## LLM judge on a seeded 200-tool test sample (needs Ollama; ~20 min per model on 8 CPU cores)
	$(PY) eval/run_eval.py --split test --judge qwen2.5:3b --judge-sample 200 --out results/metrics_judge3b.json
	$(PY) eval/run_eval.py --split test --judge qwen2.5:1.5b --judge-sample 200 --out results/metrics_judge15b.json

registry:        ## measurement scan of public remote servers in the official MCP Registry
	$(PY) scripts/registry_scan.py --limit 200
	$(PY) scripts/registry_judge.py --model qwen2.5:3b

results: eval    ## plots, README table, dashboard screenshot, banner, demo GIF
	$(PY) scripts/plots.py
	$(PY) scripts/dashboard.py
	$(PY) scripts/banner.py
	$(PY) scripts/demo_gif.py

demo:
	$(PY) -m mcp_audit scan --stdio -- $(PY) examples/poisoned_server.py
