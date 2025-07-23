.PHONY: lint test run

lint:
	ruff check .
	mypy ioc_inspector_core main.py

test:
	pytest -q

run:
	python main.py $(ARGS)
