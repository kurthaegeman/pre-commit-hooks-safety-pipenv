import io
import json
import os

import pipenv.patched.safety.constants
import pipenv.patched.safety.safety
import pipenv.patched.safety.util
import pipenv.utils.dependencies


def process_lockdata(lockdata: dict) -> list:
    # Use pipenv to list the requirements.
    pip_deps = pipenv.utils.dependencies.convert_deps_to_pip(
        lockdata["default"],
        project=None,
        include_index=False,
        include_hashes=False,
        include_markers=False,
    )
    # Avoid disk I/O by loading the requirements to a StringIO object.
    requirements = io.StringIO("\n".join(pip_deps))
    requirements_read = pipenv.patched.safety.util.read_requirements(requirements)
    vulnerabilities, _ = pipenv.patched.safety.safety.check(
        requirements_read, ignore_vulns=[], telemetry=False, cached=3600
    )
    return vulnerabilities


def main():
    # Load lockfile.
    if not os.path.exists("Pipfile.lock"):
        return 0

    # TODO: catch broken lock files
    with open("Pipfile.lock") as fp:
        pipfile_lock = json.load(fp)

    vulnerabilities = process_lockdata(pipfile_lock)

    return (
        pipenv.patched.safety.constants.EXIT_CODE_VULNERABILITIES_FOUND
        if len(vulnerabilities)
        else pipenv.patched.safety.constants.EXIT_CODE_OK
    )
