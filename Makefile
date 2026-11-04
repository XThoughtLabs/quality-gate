# make check                   runs the gate's own tests.
# make reproduce REPO= SHA=    reruns every deterministic check in the pinned container.
PY ?= python
IMAGE := python:3.13.15-slim-bookworm@sha256:2325bb286ec344af3e5898cc224b5844e2707ac6e26b1632516fd3edc84a5e26
OUT ?= reproduce-out

.PHONY: check reproduce

check:
	GATE_ROOT="$(CURDIR)" PYTHONPATH=. $(PY) -P -m pytest tests -q

reproduce:
	@test -n "$(REPO)" || (echo "give REPO=<url>" && exit 2)
	@test -n "$(SHA)" || (echo "give SHA=<sha>" && exit 2)
	mkdir -p "$(OUT)"
	docker run --rm \
	  -v "$(CURDIR):/gate:ro" \
	  -v "$(abspath $(OUT)):/out" \
	  -e PYTHONPATH=/gate \
	  -e GATE_TOKEN \
	  -e GATE_TOOLS=/tools/bin \
	  -e GATE_TOOLS_BIN=/tools-bin \
	  -e GATE_SEMGREP=/semgrep/bin \
	  "$(IMAGE)" \
	  sh -c 'apt-get update -qq && apt-get install -y -qq git curl >/dev/null \
	    && pip install --quiet --require-hashes -r /gate/locks/gate.lock \
	    && python -m venv /tools && /tools/bin/pip install --quiet --require-hashes -r /gate/locks/tools.lock \
	    && python -m venv /semgrep && /semgrep/bin/pip install --quiet --require-hashes -r /gate/locks/semgrep.lock \
	    && bash /gate/scripts/install_gitleaks.sh /tools-bin \
	    && python -P -m gate.reproduce --repo "$(REPO)" --sha "$(SHA)" --out /out'
