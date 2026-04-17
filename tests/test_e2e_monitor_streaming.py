from __future__ import annotations

from pathlib import Path


def test_pump_decodes_non_utf8_bytes_without_crashing(tmp_path: Path) -> None:
    import scripts.run_e2e_monitor as monitor

    class _FakeBinaryStream:
        def __init__(self, chunks: list[bytes]) -> None:
            self._chunks = list(chunks)

        def readline(self) -> bytes:
            if self._chunks:
                return self._chunks.pop(0)
            return b""

    out_path = tmp_path / "out.log"
    stream = _FakeBinaryStream([b"ok\n", b"bad:\xff\xfe\n"])

    monitor._pump(stream, out_path)

    text = out_path.read_text(encoding="utf-8")
    assert "ok" in text
    assert "bad:" in text
