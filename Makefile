# HugMesh user-bff-api — developer make targets.
#
# `make pentest` runs the SAME OWASP checks the GitLab CI pentest stage runs, so a
# developer can self-scan locally before pushing (mirrors .gitlab-ci.yml: the
# centralized .pentest-sca / .pentest-dast-baseline jobs from the generator repo).
#   * SCA  : OWASP Dependency-Check over this Maven project.
#   * DAST : delegates to the generator pen-test harness (run-pentest.sh) when a
#            live target ($DAST_TARGET_URL) is set; otherwise prints how to run it.
# It NEVER hard-fails on a missing target/tooling — local convenience, not a gate.

# CVSS threshold that fails the SCA build (matches the inline dependency-check job).
SCA_FAIL_CVSS ?= 9
# JDK image used for the dockerized SCA run (matches the CI security job image).
JDK_IMAGE     ?= eclipse-temurin:21-jdk-noble
# Where to find the shared DAST harness. Override if you vendor/clone it elsewhere.
PENTEST_HARNESS_DIR ?= ../hugmesh-generator/tests/pentest

.PHONY: pentest pentest-sca pentest-dast

## pentest: run the local SCA self-scan + (optionally) the DAST harness.
pentest: pentest-sca pentest-dast

## pentest-sca: OWASP Dependency-Check over this repo (CVSS>=$(SCA_FAIL_CVSS) fails).
## Prefers Docker (mirrors CI exactly); falls back to a local ./mvnw run.
pentest-sca:
	@echo "[pentest-sca] OWASP Dependency-Check (failBuildOnCVSS=$(SCA_FAIL_CVSS))"
	@if command -v docker >/dev/null 2>&1; then \
		echo "[pentest-sca] using docker image $(JDK_IMAGE) (as CI does)"; \
		docker run --rm \
			-v "$(CURDIR):/workspace" \
			-v "$(CURDIR)/.dep-check-data:/dep-check-data" \
			-w /workspace --entrypoint "" \
			$(JDK_IMAGE) \
			./mvnw org.owasp:dependency-check-maven:check \
				-Dformat=HTML,JSON \
				-DfailBuildOnCVSS=$(SCA_FAIL_CVSS) \
				-DdataDirectory=/dep-check-data \
				-DautoUpdate=true -B ; \
	elif [ -x ./mvnw ]; then \
		echo "[pentest-sca] docker not found — running ./mvnw locally"; \
		./mvnw org.owasp:dependency-check-maven:check -DfailBuildOnCVSS=$(SCA_FAIL_CVSS) -B ; \
	else \
		echo "[pentest-sca] neither docker nor ./mvnw available — skipping (non-fatal)"; \
	fi

## pentest-dast: run the shared ZAP/probes/nuclei harness against $$DAST_TARGET_URL.
## No target set => prints the invocation and exits 0 (advisory only, never a gate).
pentest-dast:
	@if [ -z "$(DAST_TARGET_URL)" ]; then \
		echo "[pentest-dast] DAST_TARGET_URL not set — skipping live DAST (non-fatal)."; \
		echo "[pentest-dast] To run the full harness against a live test env:"; \
		echo "    DAST_TARGET_URL=http://gateway.test-env:8080 make pentest-dast"; \
	elif [ -x "$(PENTEST_HARNESS_DIR)/run-pentest.sh" ]; then \
		echo "[pentest-dast] delegating to $(PENTEST_HARNESS_DIR)/run-pentest.sh"; \
		bash "$(PENTEST_HARNESS_DIR)/run-pentest.sh" --env compose --scan baseline --pipeline main ; \
	else \
		echo "[pentest-dast] harness not found at $(PENTEST_HARNESS_DIR)/run-pentest.sh"; \
		echo "[pentest-dast] clone it, e.g.:"; \
		echo "    git clone https://github.com/Snapdragon-Systems/hugmesh-generator /tmp/sg"; \
		echo "    PENTEST_HARNESS_DIR=/tmp/sg/tests/pentest make pentest-dast"; \
		echo "[pentest-dast] skipping (non-fatal)."; \
	fi
