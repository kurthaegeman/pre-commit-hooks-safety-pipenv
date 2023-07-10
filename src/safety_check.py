import argparse
import io
import json
import os

import pipenv.patched.safety.constants
import pipenv.patched.safety.safety
import pipenv.patched.safety.util
import pipenv.utils.dependencies


def build_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("files", nargs="+")
    return parser


def main(argv=None):
    # We parse the arguments, but I don't really see the point in doing
    # something with them. The goal is to scan the Pipfile.lock on every
    # commit, so we can be sure that no new security vulnerabilities creep into
    # the project. If we disable telemetry and enable the cache, we avoid
    # overloading the upstream API.
    parser = build_parser()
    parsed_args, args_rest = parser.parse_known_args(argv)
    print(parsed_args)

    # Load lockfile.
    if not os.path.exists("Pipfile.lock"):
        return 0

    with open("Pipfile.lock") as fp:
        lockdata = json.load(fp)

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
        requirements_read, ignore_vulns=[], telemetry=False, cached=60
    )

    return (
        pipenv.patched.safety.constants.EXIT_CODE_VULNERABILITIES_FOUND
        if len(vulnerabilities)
        else pipenv.patched.safety.constants.EXIT_CODE_OK
    )
