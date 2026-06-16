# Zeus Hermes Orchestrator
# Maintained by BrainX: https://github.com/brainx

.PHONY: test doctor strict-doctor repo-check verify-real-hermes fresh-vps-verify clean clean-vps

test:
	sh scripts/test.sh

doctor:
	python3 -B -m zeus.cli doctor --json

strict-doctor:
	python3 -B -m zeus.cli doctor --strict --json

repo-check:
	sh scripts/repo_check.sh

verify-real-hermes:
	sh scripts/verify_real_hermes.sh

fresh-vps-verify:
	bash scripts/fresh_vps_verify.sh

clean:
	rm -rf .zeus .zeus-real-hermes-check zeus/__pycache__ tests/__pycache__

clean-vps:
	rm -rf .zeus .zeus-real-hermes-check .zeus-vps-multi .zeus-vps-api .tmp/fresh-vps-verify
