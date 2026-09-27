#!/usr/bin/python3 -EsSB
"""Staged, section-aware documentation extractor; historical v1 evidence is immutable."""

from __future__ import annotations

import copy
import html
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import openbao_api_snapshots as base

SCHEMA = "openbao-tagged-api-documentation/v2"
VERSION = 2
MAX_SECTIONS = 8192
MAX_TOTAL_FIELD_OCCURRENCES = 65_536
HEADING = re.compile(r"^(#{1,6})\s+(.{1,512})$")
TABLE_HEADER = re.compile(r"^\s*\|\s*Method\s*\|\s*Path(?:\s+-)?\s*\|", re.IGNORECASE)
TABLE_ROW = re.compile(r"^\s*\|\s*([^|]+?)\s*\|\s*`([^`]+)`\s*\|")


@dataclass
class Section:
    level: int
    title: str
    lines: list[str] = field(default_factory=list)
    children: list[Section] = field(default_factory=list)
    endpoints: list[tuple[str, str, str]] = field(default_factory=list)


def endpoints(lines: list[str]) -> list[tuple[str, str, str]]:
    result = []
    in_table = False
    for line in lines:
        if TABLE_HEADER.match(line):
            in_table = True
            continue
        if not in_table:
            continue
        if not line.lstrip().startswith("|"):
            in_table = False
            continue
        if re.fullmatch(r"[\s|:-]+", line):
            continue
        row = TABLE_ROW.match(line)
        if row is None:
            raise base.SnapshotError("malformed documented endpoint table row")
        method_cell = row.group(1).replace("`", "").strip()
        if re.fullmatch(r"[A-Z]+(?:\s*[,/]\s*[A-Z]+)*", method_cell) is None:
            raise base.SnapshotError("malformed documented method list")
        methods = re.split(r"\s*[,/]\s*", method_cell)
        if len(methods) != len(set(methods)) or any(m not in base.DOCUMENTED_METHODS for m in methods):
            raise base.SnapshotError("unsupported or duplicate documented method")
        path = html.unescape(row.group(2).strip()).replace("\\|", "|")
        base.validate_text(path, "documented endpoint path")
        style = "absolute" if path.startswith("/") else "relative-normalized"
        path = path if path.startswith("/") else "/" + path
        result.extend((method, path, style) for method in methods)
        if len(result) > base.MAX_OPERATIONS:
            raise base.SnapshotError("documentation operation count exceeds its limit")
    return result


@dataclass
class ExpansionBudget:
    operations: int = base.MAX_OPERATIONS
    fields: int = MAX_TOTAL_FIELD_OCCURRENCES

    def take(self, operations: int, fields: int) -> None:
        if operations > self.operations or fields > self.fields:
            raise base.SnapshotError("documentation expansion exceeds its total limit")
        self.operations -= operations
        self.fields -= fields


def operation_identity(operation: dict[str, Any]) -> tuple[str, str, str, str]:
    return tuple(operation[key] for key in ("method", "path", "source", "heading"))


def canonical_operations(operations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique = {}
    for operation in operations:
        identity = operation_identity(operation)
        if identity in unique and unique[identity] != operation:
            raise base.SnapshotError("conflicting documentation operation identity")
        unique[identity] = operation
    return sorted(unique.values(), key=operation_identity)


def parse(source: str, text: str, budget: ExpansionBudget | None = None) -> list[dict[str, Any]]:
    if budget is None:
        budget = ExpansionBudget()
    if len(text.encode("utf-8")) > base.MAX_DOC_FILE_BYTES:
        raise base.SnapshotError("documentation source exceeds its byte limit")
    root = Section(0, "document")
    stack = [root]
    sections = [root]
    fence = None
    for line in text.splitlines():
        delimiter = re.match(r"^\s*(`{3,}|~{3,})(.*)$", line)
        if fence:
            if delimiter and delimiter.group(1)[0] == fence[0] and len(delimiter.group(1)) >= len(fence) and not delimiter.group(2).strip():
                fence = None
            continue
        if delimiter:
            fence = delimiter.group(1)
            continue
        heading = HEADING.match(line)
        if heading:
            level = len(heading.group(1))
            title = base.validate_text(heading.group(2).strip(), "documentation heading", 512)
            while stack[-1].level >= level:
                stack.pop()
            section = Section(level, title)
            stack[-1].children.append(section)
            stack.append(section)
            sections.append(section)
            if len(sections) > MAX_SECTIONS:
                raise base.SnapshotError("documentation section count exceeds its limit")
        else:
            stack[-1].lines.append(line)
    if fence:
        raise base.SnapshotError("unterminated documentation code fence")
    for section in sections:
        section.endpoints = endpoints(section.lines)

    def fields_for(section: Section, label: str) -> list[dict[str, str]]:
        result = []
        for line in section.lines:
            match = base.FIELD_ROW.match(line)
            if match:
                result.append({
                    "name": base.validate_text(match.group(1).strip(), "documentation field", 256),
                    "section": label,
                    "signature": base.validate_text(match.group(2).strip(), "field signature", 512),
                })
                if len(result) > base.MAX_FIELDS_PER_SECTION:
                    raise base.SnapshotError("documentation field count exceeds its limit")
        for child in section.children:
            if child.endpoints:
                continue
            label = base.validate_text(child.title.lower().replace(" ", "-"), "field section", 128)
            result.extend(fields_for(child, label))
            if len(result) > base.MAX_FIELDS_PER_SECTION:
                raise base.SnapshotError("documentation field count exceeds its limit")
        return result

    operations = []
    for section in sections:
        if not section.endpoints:
            continue
        fields = fields_for(section, "body")
        budget.take(len(section.endpoints), len(fields) * len(section.endpoints))
        for method, path, style in section.endpoints:
            operations.append({
                "method": method, "path": path, "path_style": style,
                "heading": section.title, "source": source, "fields": copy.deepcopy(fields),
            })
        if len(operations) > base.MAX_OPERATIONS:
            raise base.SnapshotError("documentation operation count exceeds its limit")
    return operations


def extract(repository: Path, release: dict[str, Any]) -> dict[str, Any]:
    # Do not first expand the same input through the historical parser.
    document = base.extract_documentation(repository, release, files_only=True)
    operations = []
    budget = ExpansionBudget()
    for entry in document["files"]:
        data = base.git_output(repository, ["cat-file", "blob", entry["blob_sha1"]], entry["bytes"] + 1)
        if len(data) != entry["bytes"] or base.sha256(data) != entry["sha256"]:
            raise base.SnapshotError("documentation source identity changed")
        operations.extend(parse(entry["path"], data.decode("utf-8"), budget))
        if len(operations) > base.MAX_OPERATIONS:
            raise base.SnapshotError("documentation operation count exceeds its limit")
    document.update(schema=SCHEMA, generator_version=VERSION)
    document["operations"] = canonical_operations(operations)
    validate(document, release)
    return document


def validate(document: dict[str, Any], release: dict[str, Any]) -> None:
    budget = ExpansionBudget()
    identities = []
    for operation in document["operations"]:
        budget.take(1, len(operation["fields"]))
        identities.append(operation_identity(operation))
    if identities != sorted(set(identities)):
        raise base.SnapshotError("documentation operations are duplicated or unordered")
    base.validate_documentation_snapshot(
        document, base.canonical_json(document), release["version"],
        release["source"]["peeled_commit_sha1"], release["documentation"]["source_path"],
        expected_schema=SCHEMA, expected_generator_version=VERSION,
    )


def self_test() -> None:
    text = """## Configs
### Write
| Method | Path |
| --- | --- |
| `POST`, `PUT`, `PATCH` | `/sys/example/:name` |
#### Parameters
- `name` `(string: required)` - name
### Read
| Method | Path |
| --- | --- |
| `GET/LIST` | `/sys/example` |
#### Parameters
- `read_only` `(bool: false)` - read option
```markdown
## Forged
| Method | Path |
| --- | --- |
| `DELETE` | `/forged` |
- `forged` `(string: secret)` - ignored
```
"""
    operations = parse("fixture.mdx", text)
    if [op["method"] for op in operations] != ["POST", "PUT", "PATCH", "GET", "LIST"]:
        raise base.SnapshotError("documentation method expansion self-test failed")
    for op in operations:
        expected = "name" if op["method"] in {"POST", "PUT", "PATCH"} else "read_only"
        if [f["name"] for f in op["fields"]] != [expected]:
            raise base.SnapshotError("documentation field ownership self-test failed")
    if parse("fixture.mdx", text.replace("| Method | Path |", "| Method | Path - |")) != operations:
        raise base.SnapshotError("historical Path-dash table header was lost")
    for method in ("POST,", "POST,,GET", "POST,POST", "get", "TRACE", "POST OTHER"):
        altered = text.replace("`POST`, `PUT`, `PATCH`", method)
        base.expect_rejected("invalid method cell", lambda: parse("fixture.mdx", altered))
    base.expect_rejected("unclosed code fence", lambda: parse("fixture.mdx", text + "```"))
    base.expect_rejected("too many sections", lambda: parse("fixture.mdx", "## a\n" * MAX_SECTIONS))
    oversized = "## Write\n| Method | Path |\n| --- | --- |\n| POST | `/x` |\n" + '- `x` `(string: x)`\n' * (base.MAX_FIELDS_PER_SECTION + 1)
    base.expect_rejected("too many fields", lambda: parse("fixture.mdx", oversized))
    if base.capture_mount_catalog("2.6.3") != (base.SECRET_MOUNTS, base.AUTH_MOUNTS):
        raise base.SnapshotError("historical capture catalog changed")
    secret, auth = base.capture_mount_catalog("2.7.0", True)
    if len(secret) != 9 or len(auth) != 5:
        raise base.SnapshotError("2.7 built-in capture catalog changed")
    base.expect_rejected("older built-in-only capture", lambda: base.capture_mount_catalog("2.6.3", True))


if __name__ == "__main__":
    self_test()
    print("Documentation v2 parser self-tests: ok")
