from __future__ import annotations

import subprocess
from pathlib import Path

SOURCE = Path("src/sentinel_core/xai_voice.py")
MAIN_TESTS = Path("tests/test_xai_voice.py")
REGRESSION_TESTS = Path("tests/test_xai_voice_review_regressions.py")
EXPECTED_MAIN_TEST_BLOB = "262a5f40e88b91d7a1d0c3564571592ff002a047"


def git_blob(path: Path) -> str:
    return subprocess.check_output(
        ["git", "hash-object", str(path)],
        text=True,
    ).strip()


def replace_once(text: str, old: str, new: str, *, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


def main() -> None:
    main_test_blob = git_blob(MAIN_TESTS)
    if main_test_blob != EXPECTED_MAIN_TEST_BLOB:
        raise RuntimeError(
            "main test blob changed: "
            f"expected {EXPECTED_MAIN_TEST_BLOB}, got {main_test_blob}"
        )

    source = SOURCE.read_text(encoding="utf-8")
    main_tests = MAIN_TESTS.read_text(encoding="utf-8")
    regression_tests = REGRESSION_TESTS.read_text(encoding="utf-8")

    source = replace_once(
        source,
        """import tempfile
import unicodedata
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Final, Iterable, Mapping, Sequence
from urllib.parse import urlencode
""",
        """import tempfile
import unicodedata
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import Any, Final, Self
from urllib.parse import urlencode
""",
        label="modern type imports",
    )

    source = replace_once(
        source,
        """    async def __aenter__(self) -> XaiVoiceClient:
        await self.connect()
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        await self.close()
""",
        """    async def __aenter__(self) -> Self:
        await self.connect()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.close()
""",
        label="async context annotations",
    )

    source = replace_once(
        source,
        """        try:
            await websocket.close(code=1000, reason=\"client shutdown\")
        except Exception:
            pass
""",
        """        try:
            await websocket.close(code=1000, reason=\"client shutdown\")
        except Exception:  # noqa: BLE001, S110 - shutdown is deliberately best-effort
            pass
""",
        label="best effort websocket close",
    )

    source = replace_once(
        source,
        """        if character in {\"\\n\", \"\\r\", \"\\t\"}:
            safe_characters.append(character)
        elif codepoint >= 32 and not 127 <= codepoint <= 159:
            safe_characters.append(character)
""",
        """        if character in {\"\\n\", \"\\r\", \"\\t\"} or (
            codepoint >= 32 and not 127 <= codepoint <= 159
        ):
            safe_characters.append(character)
""",
        label="terminal text branch",
    )

    source = replace_once(
        source,
        """    except Exception:
        print(\"ERROR: voice session failed closed\", file=sys.stderr)
        return 1
""",
        """    except Exception:  # noqa: BLE001 - CLI intentionally suppresses sensitive detail
        print(\"ERROR: voice session failed closed\", file=sys.stderr)
        return 1
""",
        label="fail closed CLI exception",
    )

    main_tests = replace_once(
        main_tests,
        """    XaiVoiceProtocolError,
    XaiVoiceRemoteError,
    build_user_turn_events,
    create_pcm16_wav,
    parse_server_event,
    persist_voice_response,
    _safe_terminal_text,
)
""",
        """    XaiVoiceProtocolError,
    XaiVoiceRemoteError,
    _safe_terminal_text,
    build_user_turn_events,
    create_pcm16_wav,
    parse_server_event,
    persist_voice_response,
)
""",
        label="main test import order",
    )

    regression_tests = replace_once(
        regression_tests,
        """import sentinel_core.xai_voice as xai_voice
from sentinel_core.xai_voice import (
""",
        """from sentinel_core import xai_voice
from sentinel_core.xai_voice import (
""",
        label="regression module import",
    )

    SOURCE.write_text(source, encoding="utf-8")
    MAIN_TESTS.write_text(main_tests, encoding="utf-8")
    REGRESSION_TESTS.write_text(regression_tests, encoding="utf-8")


if __name__ == "__main__":
    main()
