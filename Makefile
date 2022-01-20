APP = r2analyze

SHELL = /bin/bash
DIR = $(shell pwd)

NO_COLOR=\033[0m
OK_COLOR=\033[32;01m
ERROR_COLOR=\033[31;01m
WARN_COLOR=\033[33;01m
MAKE_COLOR=\033[33;01m%-20s\033[0m
PYTHON=python3
BUILD_OPTS=bdist_wheel

.DEFAULT_GOAL := help

.PHONY: help
help:
	@echo -e "$(OK_COLOR)==== $(APP) ====$(NO_COLOR)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(MAKE_COLOR) : %s\n", $$1, $$2}'

.PHONY: build
build: ## Build pip package
	@echo -e "Building $(OK_COLOR)[$(APP)]$(NO_COLOR) package"
	@$(PYTHON) ./setup.py $(BUILD_OPTS)

.PHONY: clean
clean: ## Remove folders created by build
	@rm -rf build/ dist/ ${APP}.egg-info/

.PHONY: upload
upload: ## Upload package to pypi
	@echo -e "Uploading $(OK_COLOR)[$(APP)]$(NO_COLOR) to pypi"
	@twine upload dist/*