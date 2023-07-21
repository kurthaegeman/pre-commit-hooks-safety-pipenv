import json
from pathlib import Path

import pytest

from src.safety_check import parse_commandline_args, process_lockdata

RESOURCE_DIR = Path(__file__).parent.resolve() / "resources"


@pytest.mark.parametrize(
    "argv, expected",
    [
        ([], ["default"]),
        (["--categories=develop"], ["develop"]),
        (["--categories", "develop"], ["develop"]),
        (["--categories=develop, default, staging"], ["develop", "default", "staging"]),
        (["--categories=develop default staging"], ["develop", "default", "staging"]),
        (
            ["--categories", "develop default staging"],
            ["develop", "default", "staging"],
        ),
        (
            ["--categories", "develop, default, staging"],
            ["develop", "default", "staging"],
        ),
        (
            ["--categories", "develop,default,staging"],
            ["develop", "default", "staging"],
        ),
    ],
)
def test_parse_commandline_args__categories(argv, expected):
    actual = parse_commandline_args(argv)
    assert actual.categories == expected


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
    vulnerabilities = process_lockdata(test_data, ["default"])
    assert vulnerabilities == []


def test_process_lockdata__vulnerability_found(resource):
    test_data = json.loads(resource)
    vulnerabilities = process_lockdata(test_data, ["default"])
    assert len(vulnerabilities) > 0


@pytest.mark.parametrize(
    "categories, nrof_vulnerabilities",
    [
        (["default"], 1),
        (["develop"], 0),
        (["staging"], 1),
        (["default", "develop"], 1),
        (["develop", "staging"], 1),
        (["default", "staging"], 2),
        (["default", "develop", "staging"], 2),
    ],
)
def test_process_lockdata__categories(resource, categories, nrof_vulnerabilities):
    test_data = json.loads(resource)
    vulnerabilities = process_lockdata(test_data, categories)
    assert len(vulnerabilities) == nrof_vulnerabilities
