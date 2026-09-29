import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_tests_directory_is_the_only_python_test_tree():
    stray = [
        path.relative_to(ROOT)
        for path in ROOT.rglob("test_*.py")
        if "tests" not in path.relative_to(ROOT).parts[:1] and ".venv" not in path.parts and "node_modules" not in path.parts
    ]
    assert stray == [], f"Python tests outside tests/: {stray}"


def test_elasticsearch_contract_files_are_valid_json():
    files = list((ROOT / "elk/elasticsearch/index-templates").glob("*.json"))
    files += list((ROOT / "elk/elasticsearch/mapping-upgrades").glob("*.json"))
    assert files
    for path in files:
        assert isinstance(json.loads(path.read_text()), dict), path
