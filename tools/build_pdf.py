#!/usr/bin/env python3
"""Generate a compact, dependency-free PDF from a Markdown document.

This intentionally produces a text-first PDF suitable for project handoff.
For typeset documentation, use Pandoc or another dedicated publishing tool.
"""

from __future__ import annotations

import re
import sys
import textwrap
from pathlib import Path

PAGE_WIDTH, PAGE_HEIGHT = 595, 842  # A4 points
MARGIN, LEADING, MAX_LINES = 48, 14, 48


def pdf_string(value: str) -> bytes:
    encoded = value.encode("cp1252", errors="replace")
    return encoded.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)")


def markdown_lines(markdown: str) -> list[str]:
    lines: list[str] = []
    for raw in markdown.splitlines():
        line = raw.strip()
        if not line:
            lines.append("")
            continue
        if line.startswith("|") and not re.fullmatch(r"[| :\-]+", line):
            line = "  ".join(part.strip() for part in line.strip("|").split("|"))
        line = re.sub(r"^#{1,6}\s*", "", line)
        line = re.sub(r"^[-*]\s+", "• ", line)
        line = re.sub(r"`([^`]*)`", r"\1", line)
        line = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", line)
        line = line.replace("**", "").replace("_", "")
        lines.extend(textwrap.wrap(line, width=92, subsequent_indent="  ") or [""])
    return lines


def build_pdf(lines: list[str]) -> bytes:
    pages = [lines[index:index + MAX_LINES] for index in range(0, len(lines), MAX_LINES)] or [[]]
    objects: list[bytes] = [b"<< /Type /Catalog /Pages 2 0 R >>"]
    page_ids, content_ids = [], []
    # Object ids: catalog=1, pages=2, font=3, then page/content pairs.
    font_id = 3
    next_id = 4
    for _ in pages:
        page_ids.append(next_id)
        content_ids.append(next_id + 1)
        next_id += 2
    kids = b" ".join(f"{page_id} 0 R".encode() for page_id in page_ids)
    objects.append(b"<< /Type /Pages /Kids [" + kids + b"] /Count " + str(len(pages)).encode() + b" >>")
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
    for page_id, content_id, page_lines in zip(page_ids, content_ids, pages):
        objects.append(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_WIDTH} {PAGE_HEIGHT}] "
            f"/Resources << /Font << /F1 {font_id} 0 R >> >> /Contents {content_id} 0 R >>".encode()
        )
        stream = [b"BT", b"/F1 10 Tf", f"{MARGIN} {PAGE_HEIGHT - MARGIN} Td".encode(), f"{LEADING} TL".encode()]
        for line in page_lines:
            stream.append(b"(" + pdf_string(line) + b") Tj")
            stream.append(b"T*")
        stream.append(b"ET")
        content = b"\n".join(stream)
        objects.append(b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n" + content + b"\nendstream")

    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for number, obj in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{number} 0 obj\n".encode())
        output.extend(obj)
        output.extend(b"\nendobj\n")
    xref = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode())
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode())
    output.extend(f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
    return bytes(output)


def main() -> int:
    if len(sys.argv) != 3:
        print(f"Uso: {Path(sys.argv[0]).name} ENTRADA.md SALIDA.pdf", file=sys.stderr)
        return 2
    source, destination = map(Path, sys.argv[1:])
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(build_pdf(markdown_lines(source.read_text(encoding="utf-8"))))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
