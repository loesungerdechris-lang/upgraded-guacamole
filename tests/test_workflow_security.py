from textwrap import dedent

import pytest

from sentinel_core.workflow_security import validate_workflow_text

CHECKOUT_SHA = "34e114876b0b11c390a56381ad16ebd13914f8d5"
SETUP_SHA = "a26af69be951a213d495a4c3e4e4022e16d87065"


def _workflow(step: str) -> str:
    return dedent(
        f"""
        name: test
        on: workflow_dispatch
        permissions:
          contents: read
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
        {step}
        """
    )


def test_accepts_pinned_checkout_with_credentials_disabled() -> None:
    text = _workflow(
        dedent(
            f"""
                  - name: Checkout
                    uses: actions/checkout@{CHECKOUT_SHA}
                    with:
                      fetch-depth: 0
                      persist-credentials: false
            """
        )
    )
    assert validate_workflow_text(text) == []


def test_accepts_pinned_remote_and_local_actions() -> None:
    text = _workflow(
        dedent(
            f"""
                  - uses: actions/setup-python@{SETUP_SHA}
                  - uses: ./local-action
            """
        )
    )
    assert validate_workflow_text(text) == []


@pytest.mark.parametrize(
    "uses_line",
    [
        "          - uses: actions/checkout@v4",
        "          - {uses: actions/checkout@v4}",
        f"          - 'uses': actions/checkout@{CHECKOUT_SHA}",
        f"          - uses : actions/checkout@{CHECKOUT_SHA}",
        "          - uses:",
    ],
)
def test_rejects_mutable_or_ambiguous_uses_syntax(uses_line: str) -> None:
    failures = validate_workflow_text(_workflow(uses_line))
    assert failures


def test_rejects_duplicate_uses_keys_in_one_step() -> None:
    text = _workflow(
        dedent(
            f"""
                  - name: Invalid
                    uses: actions/setup-python@{SETUP_SHA}
                    uses: actions/checkout@{CHECKOUT_SHA}
                    with:
                      persist-credentials: false
            """
        )
    )
    failures = validate_workflow_text(text)
    assert any("duplicate uses" in failure for failure in failures)


@pytest.mark.parametrize(
    "with_block",
    [
        "",
        "              persist-credentials: true",
        "              persist-credentials: false\n              persist-credentials: false",
        "              'persist-credentials': false",
        "              {persist-credentials: false}",
    ],
)
def test_rejects_checkout_credential_bypass(with_block: str) -> None:
    with_section = f"\n            with:\n{with_block}" if with_block else ""
    text = _workflow(
        f"          - uses: actions/checkout@{CHECKOUT_SHA}{with_section}"
    )
    failures = validate_workflow_text(text)
    assert failures


def test_rejects_persist_credentials_under_env() -> None:
    text = _workflow(
        dedent(
            f"""
                  - uses: actions/checkout@{CHECKOUT_SHA}
                    env:
                      persist-credentials: false
            """
        )
    )
    failures = validate_workflow_text(text)
    assert any("with mapping" in failure for failure in failures)


def test_rejects_nested_persist_credentials_inside_with() -> None:
    text = _workflow(
        dedent(
            f"""
                  - uses: actions/checkout@{CHECKOUT_SHA}
                    with:
                      env:
                        persist-credentials: false
            """
        )
    )
    failures = validate_workflow_text(text)
    assert failures
    assert any("checkout" in failure for failure in failures)


def test_ignores_uses_text_inside_yaml_comment() -> None:
    text = _workflow(
        dedent(
            f"""
                  # uses: untrusted/action@main
                  - uses: actions/setup-python@{SETUP_SHA}
            """
        )
    )
    assert validate_workflow_text(text) == []
