import argparse
import io
import json
import re
import sys

import pipenv.patched.safety.constants
import pipenv.patched.safety.safety
import pipenv.patched.safety.util
import pipenv.utils.dependencies


class AppendStringAction(argparse.Action):  # pylint: disable=too-few-public-methods
    def __call__(self, _, namespace, values, option_string=None):
        parsed = set(re.split(r", *| ", values))
        setattr(namespace, self.dest, parsed)


def parse_commandline_args(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--categories",
        dest="categories",
        default={"default"},
        action=AppendStringAction,
    )
    parser.add_argument("--caching", dest="caching", default=3600, type=int)
    parser.add_argument("--telemetry", dest="telemetry", action="store_true")

    return parser.parse_args(argv)


def process_lockdata(lockdata: dict, args: argparse.Namespace) -> list:
    # Collect the dependencies for all selected categories.
    deps = {}
    for cat in args.categories:
        deps.update(lockdata.get(cat, {}))

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
        requirements_read,
        ignore_vulns=[],
        telemetry=args.telemetry,
        cached=args.caching,
    )
    return vulnerabilities


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    args = parse_commandline_args(argv)

    # Load lockfile.
    try:
        with open("Pipfile.lock", encoding="utf-8") as fp_lock:
            pipfile_lock = json.load(fp_lock)
    except FileNotFoundError:
        print("Could not find Pipfile.lock")
        return 1
    except json.JSONDecodeError:
        print("Pipfile.lock is not valid JSON")
        return 1

    # Check categories. Fail if one doesn't exist.
    #
    # It is a design decision to fail if someone configures this hook to run on
    # a package category that doesn't exist. If this hook would silently ignore
    # non-existing package groups, a typo could result in an entire group not
    # being scanned.
    missing = set(args.categories) - set(pipfile_lock)
    if missing:
        print(f"Categories not found: {', '.join(missing)}")
        return 1

    vulnerabilities = process_lockdata(pipfile_lock, args=args)

    return (
        pipenv.patched.safety.constants.EXIT_CODE_VULNERABILITIES_FOUND
        if len(vulnerabilities)
        else pipenv.patched.safety.constants.EXIT_CODE_OK
    )


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))  # pragma: no cover
