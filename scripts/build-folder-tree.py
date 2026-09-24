#!/usr/bin/env python3
"""Walk the iot-honeypot-ids directory and produce a JSON tree for the preview page."""
import json
import os
from pathlib import Path

ROOT = Path("/home/z/my-project/iot-honeypot-ids")
OUT = Path("/home/z/my-project/public/folder-tree.json")


def build_tree(path: Path, name: str | None = None) -> dict:
    """Recursively build a tree node."""
    node = {
        "name": name if name else path.name,
        "path": str(path.relative_to(ROOT.parent)),
        "type": "directory" if path.is_dir() else "file",
    }
    if path.is_dir():
        children = []
        try:
            for entry in sorted(path.iterdir(), key=lambda p: (p.is_file(), p.name.lower())):
                # Skip noise
                if entry.name in {"__pycache__", ".venv", ".pytest_cache", "node_modules"}:
                    continue
                children.append(build_tree(entry, entry.name))
        except (PermissionError, OSError):
            pass
        node["children"] = children
    else:
        try:
            node["size"] = path.stat().st_size
        except OSError:
            node["size"] = 0
        # Tag file types for icon
        suffix = path.suffix.lower()
        if suffix in {".py"}:
            node["lang"] = "python"
        elif suffix in {".ts", ".tsx"}:
            node["lang"] = "typescript"
        elif suffix in {".js", ".jsx", ".mjs", ".cjs"}:
            node["lang"] = "javascript"
        elif suffix == ".sh":
            node["lang"] = "bash"
        elif suffix == ".ps1":
            node["lang"] = "powershell"
        elif suffix in {".yml", ".yaml"}:
            node["lang"] = "yaml"
        elif suffix == ".json":
            node["lang"] = "json"
        elif suffix == ".md":
            node["lang"] = "markdown"
        elif suffix == ".html":
            node["lang"] = "html"
        elif suffix == ".css":
            node["lang"] = "css"
        elif suffix in {".txt", ".cfg", ".ini"}:
            node["lang"] = "text"
        elif suffix == ".csv":
            node["lang"] = "csv"
        elif suffix == ".jsonl":
            node["lang"] = "jsonl"
        else:
            node["lang"] = "file"
    return node


def count_stats(node: dict) -> dict:
    """Compute file count + total size for a tree."""
    if node["type"] == "file":
        return {"files": 1, "dirs": 0, "size": node.get("size", 0)}
    files = dirs = size = 0
    for child in node.get("children", []):
        s = count_stats(child)
        files += s["files"]
        dirs += s["dirs"]
        size += s["size"]
    return {"files": files, "dirs": dirs + 1, "size": size}


tree = build_tree(ROOT, "iot-honeypot-ids")
stats = count_stats(tree)
tree["stats"] = stats

OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps(tree, indent=2))
print(f"Wrote {OUT} — {stats['files']} files, {stats['dirs']} dirs, {stats['size']} bytes")
