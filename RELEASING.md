# Releasing

The project is not on PyPI yet. Until it is, the README tells people to install
from source, which works today and needs nothing from you.

This document is what to do when you decide to publish.

## Before the first release

**1. Claim the name.** `sagan2sigma` is unclaimed on PyPI at the time of
writing, but names are first come, first served. Register an account and, if
you want to hold the name before the code is ready, upload once to
[TestPyPI](https://test.pypi.org) first to rehearse the whole flow.

**2. Set up trusted publishing.** The CI workflow uses OIDC rather than a
stored API token, which means there is no long-lived secret to leak or rotate.
On PyPI, go to your account's *Publishing* section and add a pending publisher:

| Field | Value |
| --- | --- |
| PyPI project name | `sagan2sigma` |
| Owner | your GitHub account or organisation |
| Repository name | `sagan2sigma` |
| Workflow name | `ci.yml` |
| Environment name | `pypi` |

**3. Create the environment on GitHub.** Settings → Environments → New
environment, named `pypi`. Adding a required reviewer here is worth it: it
turns every publish into something you approve explicitly rather than something
a tag triggers silently.

## Cutting a release

**1. Update the version in two places.** They must agree:

```sh
# pyproject.toml
version = "0.2.0"

# src/sagan2sigma/__init__.py
__version__ = "0.2.0"
```

**2. Move the changelog.** Rename `## [Unreleased]` to `## [0.2.0]` and open a
fresh `## [Unreleased]` above it.

**3. Check the build locally** before asking CI to do it:

```sh
python -m build
python -m venv /tmp/check
/tmp/check/bin/pip install dist/*.whl
/tmp/check/bin/sagan2sigma --version
```

**4. Tag and push.** The `publish` job is gated on
`startsWith(github.ref, 'refs/tags/v')`, so nothing happens without the `v`:

```sh
git tag -a v0.2.0 -m "Release 0.2.0"
git push origin v0.2.0
```

The job runs only after `lint`, `test`, `minimum-versions`, `packaging`, `vrl`,
`differential` and `corpus` have all passed. A red build means no upload, which
is the intended behaviour.

## If something goes wrong

**PyPI does not allow re-uploading a version**, even after deletion. If a bad
artefact ships, yank it and release a patch version. There is no fixing 0.2.0
in place.

To rehearse without that risk, publish to TestPyPI first by pointing the
publish step at it:

```yaml
- uses: pypa/gh-action-pypi-publish@release/v1
  with:
    repository-url: https://test.pypi.org/legacy/
```

Then install from there to confirm the package is usable:

```sh
pip install --index-url https://test.pypi.org/simple/ \
  --extra-index-url https://pypi.org/simple/ sagan2sigma
```

The extra index is needed because TestPyPI does not mirror the dependencies.

## Licence reminder

The project is GPL-2.0-only, and so are the rules it produces, since they are
derivative works of the Sagan corpus. Nothing about publishing to PyPI changes
that; the classifier and `LICENSE` file already state it.
