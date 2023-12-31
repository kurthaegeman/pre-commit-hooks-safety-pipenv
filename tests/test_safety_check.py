import argparse
import json
from pathlib import Path
from unittest.mock import mock_open

import pipenv
import pytest
from pipenv import pep508checker

from safety_check import (
    main,
    parse_commandline_args,
    process_lockdata,
    process_requires,
)

RESOURCE_DIR = Path(__file__).parent.resolve() / "resources"


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


def test_requires(monkeypatch):
    monkeypatch.setattr(pep508checker, "lookup", {"python_version": "3.8"})
    test_data = {"_meta": {"requires": {"python_version": "3.8"}}}
    args = parse_commandline_args([])
    failed = process_requires(test_data)
    assert failed == []


def test_requires__failure(monkeypatch):
    monkeypatch.setattr(pep508checker, "lookup", {"python_version": "3.9"})
    test_data = {"_meta": {"requires": {"python_version": "3.8"}}}
    args = parse_commandline_args([])
    failed = process_requires(test_data)
    assert failed == [("python_version", "3.8", "3.9")]


def test_process_lockdata(resource):
    # TODO: average_pipfile is going to produce vulnerabilities at some point in the future
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
        ([], 1),
        (["--categories=develop"], 0),
        (["--categories=staging"], 1),
        (["--categories=default,develop"], 1),
        (["--categories=develop,staging"], 1),
        (["--categories=default,staging"], 2),
        (["--categories=default,develop,staging"], 2),
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
    mocker.patch("pipenv.pep508checker.lookup", {})
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
