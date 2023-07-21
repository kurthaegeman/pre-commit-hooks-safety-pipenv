import argparse
import io
import json
import os
import re
import sys

import pipenv.patched.safety.constants
import pipenv.patched.safety.safety
import pipenv.patched.safety.util
import pipenv.utils.dependencies


class AppendStringAction(argparse.Action):  # pylint: disable=too-few-public-methods
    def __call__(self, _, namespace, values, option_string=None):
        parsed = [v for v in re.split(r", *| ", values)]
        setattr(namespace, self.dest, parsed)


def parse_commandline_args(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--categories",
        dest="categories",
        default=["default"],
        action=AppendStringAction,
    )

    return parser.parse_args(argv)


def process_lockdata(lockdata: dict, categories: list) -> list:
    # Collect the dependencies for all selected categories.
    deps = dict()
    for cat in categories:
        deps.update(lockdata.get(cat))

    # Use pipenv to list the requirements.
    pip_deps = pipenv.utils.dependencies.convert_deps_to_pip(
        deps=deps,
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


def main() -> int:
    args = parse_commandline_args(sys.argv[1:])

    # Load lockfile.
    if not os.path.exists("Pipfile.lock"):
        return 0

    # TODO: catch broken lock files
    with open("Pipfile.lock") as fp:
        pipfile_lock = json.load(fp)

    vulnerabilities = process_lockdata(pipfile_lock, categories=args.categories)

    return (
        pipenv.patched.safety.constants.EXIT_CODE_VULNERABILITIES_FOUND
        if len(vulnerabilities)
        else pipenv.patched.safety.constants.EXIT_CODE_OK
    )


if __name__ == "__main__":
    raise SystemExit(main())
