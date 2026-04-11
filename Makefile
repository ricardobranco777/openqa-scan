FILES=*.py

.PHONY: all
all: mypy black pylint pytest

.PHONY: pylint
pylint:
	@pylint $(FILES)

.PHONY: pytest
pytest:
	pytest tests/test_*.py

.PHONY: mypy
mypy:
	@mypy $(FILES)

.PHONY: black
black:
	@black --check $(FILES)
