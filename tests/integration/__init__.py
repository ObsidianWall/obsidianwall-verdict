
# tests/integration/__init__.py
#
# Integration test suite for ObsidianWall Verdict.
#
# Integration tests invoke the full CLI pipeline using
# typer's CliRunner with real fixture files. No mocking.
# They test that commands are correctly wired, policies
# load and validate, plans parse, and decisions are
# produced end-to-end.
#
# Test files:
#   test_cli_wiring.py         Command registration and --help
#   test_evaluate_command.py   Full evaluate pipeline
#   test_coverage_command.py   Full coverage pipeline
#   test_simulate_command.py   Full simulate pipeline
#   test_validate_command.py   Policy validation pipeline