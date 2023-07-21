import json
from pathlib import Path
from unittest.mock import mock_open

import pytest

from safety_check import main, parse_commandline_args, process_lockdata

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


def test_process_lockdata__non_existent_category(resource):
    test_data = json.loads(resource)
    vulnerabilities = process_lockdata(test_data, ["staging"])
    assert vulnerabilities == []


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
