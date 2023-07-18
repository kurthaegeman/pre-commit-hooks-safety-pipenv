import json
from pathlib import Path

from src.safety_check import process_lockdata

RESOURCE_DIR = Path(__file__).parent.resolve() / "resources"


def load_resources(folder: str):
    files = list((RESOURCE_DIR / folder).rglob("*"))
    ids = [file.name for file in files]
    resources = [file.read_text() for file in files]
    return ids, resources


def pytest_generate_tests(metafunc):
    if "resource" in metafunc.fixturenames:
        ids, resources = load_resources(metafunc.definition.name)
        metafunc.parametrize("resource", resources, ids=ids)


def test_process_lockdata(resource):
    # TODO: average_pipfile is going to produce vulnerabilities at some point in the future
    test_data = json.loads(resource)
    vulnerabilities = process_lockdata(test_data)
    assert vulnerabilities == []


def test_process_lockdata__vulnerability_found(resource):
    test_data = json.loads(resource)
    vulnerabilities = process_lockdata(test_data)
    assert len(vulnerabilities) > 0
