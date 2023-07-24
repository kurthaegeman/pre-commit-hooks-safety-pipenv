# pre-commit-hooks-safety-pipenv

A pre-commit hook to check your Python pipenv-based project against
[safety-db](https://github.com/pyupio/safety-db). This is configured to run on
every commit, not just on commits that change the Pipfile or Pipfile.lock.

As the free version of the vulnerabilities database is synced once per month
([each first of the
month](https://github.com/pyupio/safety-db/commits/master)), there's no point
in pulling it in on each run and thus this hook wil cache it locally for faster
execution times.

## How to use

Add the following repo to your `.pre-commit-config.yaml`:

```yaml
- repo: https://github.com/kurthaegeman/pre-commit-hooks-safety-pipenv
  rev: 0.0.1
  hooks:
    - id: pipenv-safety-check
```

## Configuration options

### Specifying package categories

This hook supports specifying [pipenv package
categories](https://pipenv.pypa.io/en/latest/specifiers/#specifying-package-categories).
In most cases, you'd just be interested in scanning the dependencies for the
default package group, where all the dependencies go if you do a `pipenv
install <pkg>`. This is the default behaviour for this hook.

If you want to check the default _and_ the dev dependencies (installed with
`pipenv install --dev`), add `args` to your hook configuration.

```yaml
- repo: https://github.com/kurthaegeman/pre-commit-hooks-safety-pipenv
  rev: 0.0.1
  hooks:
    - id: pipenv-safety-check
      args: ["--categories=default,develop"]
```

You can also add your custom package categories.

```yaml
- repo: https://github.com/kurthaegeman/pre-commit-hooks-safety-pipenv
  rev: 0.0.1
  hooks:
    - id: pipenv-safety-check
      args: ["--categories", "develop default staging"]
```

If you configure the hook to scan a package category that does not exist in the
lock file, `pre-commit-hooks-safety-pipenv` will fail. This is to ensure that a
simple typo in the configuration does not cause an entire group of dependencies
to be ignored in the scan.

```
check pipfile lock for insecure packages.................................Failed
- hook id: pipenv-safety-check
- duration: 0.36s
- exit code: 1

Categories not found: staging
```

### Other options

To reduce the load on pyup.io and to speed up unit testing the default options are to disable telemetry with caching set to 1hr.
This is however configurable using the `--telemetry` and `--caching=` arguments

```yaml
- repo: https://github.com/kurthaegeman/pre-commit-hooks-safety-pipenv
  rev: 0.0.1
  hooks:
    - id: pipenv-safety-check
      args: ["--telemetry"]
```

```yaml
- repo: https://github.com/kurthaegeman/pre-commit-hooks-safety-pipenv
  rev: 0.0.1
  hooks:
    - id: pipenv-safety-check
      args: ["--caching=1000"]
```
