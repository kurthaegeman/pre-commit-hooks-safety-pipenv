import json
from pathlib import Path
from unittest.mock import mock_open

import pytest
from pipenv.patched.safety.util import SafetyContext

from safety_check import main, parse_commandline_args, process_lockdata

RESOURCE_DIR = Path(__file__).parent.resolve() / "resources"
TEST_DATABASE = str(Path(RESOURCE_DIR) / "database")

# Use our local copy of the SafetyDB database for consistent test results.
safety_context = SafetyContext()
safety_context.db_mirror = TEST_DATABASE


@pytest.mark.parametrize(
    "argv, expected",
    [
        ([], {"default"}),
        (["--categories=develop"], {"develop"}),
        (["--categories", "develop"], {"develop"}),
        (["--categories=develop, default, staging"], {"develop", "default", "staging"}),
        (["--categories=develop default staging"], {"develop", "default", "staging"}),
        (
            ["--categories", "develop default staging"],
            {"develop", "default", "staging"},
        ),
        (
            ["--categories", "develop, default, staging"],
            {"develop", "default", "staging"},
        ),
        (
            ["--categories", "develop,default,staging"],
            {"develop", "default", "staging"},
        ),
    ],
)
def test_parse_commandline_args__categories(argv, expected):
    actual = parse_commandline_args(argv)
    assert actual.categories == expected


@pytest.mark.parametrize(
    "argv, expected",
    [
        ([], False),
        (["--categories=develop"], False),
        (["--telemetry"], True),
    ],
)
def test_parse_commandline_args__telemetry(argv, expected):
    actual = parse_commandline_args(argv)
    assert actual.telemetry == expected


@pytest.mark.parametrize(
    "argv, expected",
    [
        ([], 3600),
        (["--categories=develop"], 3600),
        (["--caching=1000"], 1000),
        (["--caching", "1000"], 1000),
        (["--caching=0"], 0),
    ],
)
def test_parse_commandline_args__caching(argv, expected):
    actual = parse_commandline_args(argv)
    assert actual.caching == expected


@pytest.mark.parametrize(
    "argv, expected",
    [
        ([], {}),
        (["--ignore=1000"], {"1000": {"expires": None, "reason": ""}}),
        (
            ["--ignore=1000,2000"],
            {
                "1000": {"expires": None, "reason": ""},
                "2000": {"expires": None, "reason": ""},
            },
        ),
        (["--ignore", "1000"], {"1000": {"expires": None, "reason": ""}}),
        (
            ["-i", "1000,2000"],
            {
                "1000": {"expires": None, "reason": ""},
                "2000": {"expires": None, "reason": ""},
            },
        ),
    ],
)
def test_parse_commandline_args__ignore(argv, expected):
    actual = parse_commandline_args(argv)
    assert actual.ignore == expected


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
    test_data = json.loads(resource)
    args = parse_commandline_args([])
    vulnerabilities = process_lockdata(test_data, args=args)
    assert vulnerabilities == []


def test_process_lockdata__vulnerability_found(resource):
    test_data = json.loads(resource)
    args = parse_commandline_args([])
    vulnerabilities = process_lockdata(test_data, args=args)
    assert len(vulnerabilities) > 0


def test_process_lockdata__non_existent_category(resource):
    test_data = json.loads(resource)
    args = parse_commandline_args(["--categories=staging"])
    vulnerabilities = process_lockdata(test_data, args=args)
    assert vulnerabilities == []


@pytest.mark.parametrize(
    "argv, nrof_vulnerabilities",
    [
        ([], 2),
        (["--categories=develop"], 0),
        (["--categories=staging"], 1),
        (["--categories=default,develop"], 2),
        (["--categories=develop,staging"], 1),
        (["--categories=default,staging"], 3),
        (["--categories=default,develop,staging"], 3),
    ],
)
def test_process_lockdata__categories(resource, argv, nrof_vulnerabilities):
    test_data = json.loads(resource)
    args = parse_commandline_args(argv)
    vulnerabilities = process_lockdata(test_data, args=args)
    assert len(vulnerabilities) == nrof_vulnerabilities


@pytest.mark.parametrize(
    "argv, nrof_vulnerabilities",
    [
        ([], 2),
        (["--ignore=58758"], 1),
        (["--ignore", "58713"], 1),
        (["-i", "58758"], 1),
        (["--ignore=58758,58713"], 0),
        (["--ignore", "58758,58713"], 0),
        (["-i", "58758,58713"], 0),
    ],
)
def test_process_lockdata__ignore(resource, argv, nrof_vulnerabilities):
    test_data = json.loads(resource)
    args = parse_commandline_args(argv)
    vulnerabilities = process_lockdata(test_data, args=args)
    assert len(vulnerabilities) == nrof_vulnerabilities


def test_main(mocker, resource):
    mocker.patch("builtins.open", mock_open(read_data=resource))
    return_code = main([])
    assert return_code == 0


def test_main__missing_lockfile(mocker, capsys):
    mocker.patch("builtins.open", side_effect=FileNotFoundError)
    return_code = main([])
    assert return_code == 1
    assert "not find" in capsys.readouterr().out


def test_main__invalid_json(mocker, capsys):
    mocker.patch("builtins.open", mock_open(read_data="{ now_this_is_invalid_json:"))
    return_code = main([])
    assert return_code == 1
    assert "not valid" in capsys.readouterr().out


def test_main__missing_category(mocker, capsys, resource):
    mocker.patch("builtins.open", mock_open(read_data=resource))
    return_code = main(["--categories", "develop,default,staging"])
    assert return_code == 1
    assert "staging" in capsys.readouterr().out
