# Airlock -- common tasks.
PYTHON ?= .venv/bin/python
CAPTURE ?= captures/lab-synthetic.pcap

.PHONY: help setup test handshake attacks synth analyze report demo clean

help:
	@echo "setup      create the virtualenv and install dependencies"
	@echo "test       run the full test suite"
	@echo "handshake  run one authenticated Diffie-Hellman handshake"
	@echo "attacks    run every adversary simulation"
	@echo "synth      regenerate the synthetic lab capture"
	@echo "analyze    analyze \$$CAPTURE (default: $(CAPTURE))"
	@echo "report     write docs/sample-report.txt and a JSON report"
	@echo "demo       handshake, attacks, and capture analysis end to end"

setup:
	python3 -m venv .venv
	$(PYTHON) -m pip install --quiet --upgrade pip
	$(PYTHON) -m pip install --quiet -r requirements.txt
	@echo "done. run 'make demo'"

test:
	$(PYTHON) -m pytest tests/ -q

handshake:
	$(PYTHON) -m akex handshake

attacks:
	$(PYTHON) -m akex attacks

synth:
	$(PYTHON) -m wifi synth $(CAPTURE)

analyze:
	$(PYTHON) -m wifi analyze $(CAPTURE)

report: synth
	$(PYTHON) -m wifi analyze $(CAPTURE) --json captures/reports/lab-synthetic.json \
		> docs/sample-report.txt
	@echo "wrote docs/sample-report.txt and captures/reports/lab-synthetic.json"

demo: handshake attacks analyze

clean:
	rm -rf __pycache__ */__pycache__ .pytest_cache
	rm -f captures/reports/*.json
