PY ?= .venv/bin/python
CAMPAIGN ?= data/raw/campaign_v1

.PHONY: deps firmware flash test figures paper lab

deps:
	cd firmware && ./fetch_deps.sh
	python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

firmware:
	cmake -S firmware -B firmware/build && $(MAKE) -C firmware/build

flash: firmware
	st-flash --reset write firmware/build/sare_fw.bin 0x08000000

test:
	$(PY) -m pytest -q analysis/tests

figures:
	cd analysis && ../$(PY) figures.py ../$(CAMPAIGN) --out ../paper/figures --tables ../data/processed

paper:
	cd paper && latexmk -pdf main.tex

lab:
	$(PY) -m jupyter lab --notebook-dir=notebooks
