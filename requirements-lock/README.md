# Dependency locks

These files are generated with `uv pip compile --generate-hashes`. Runtime
locks are the inputs to Debian package builds; CI locks add the test and lint
dependencies from `requirements-tests.txt`.

`pip-bootstrap.txt` is intentionally small and maintained from the `pip` entry
in the generated locks. Debian's patched virtualenv exposes its seeded pip only
as `python -m pip`, so the package hook installs this exact hashed wheel before
building Squall itself.

The package workflow currently builds only on x86-64. Libtorrent 2.1.2 wheels
are published as GitHub release assets rather than on PyPI. The source
requirements declare this additional wheel source, and lock installation also
passes it explicitly:

```text
https://github.com/arvidn/libtorrent/releases/expanded_assets/v2.1.2
```

Regenerate a lock after changing either requirements input with:

```sh
uv pip compile requirements.txt --generate-hashes \
  --python-platform x86_64-manylinux_2_17 --python-version 3.12 \
  --find-links https://github.com/arvidn/libtorrent/releases/expanded_assets/v2.1.2 \
  --output-file requirements-lock/runtime-py312-linux-x86_64.txt
```

Use Python 3.13 for the other runtime lock. Substitute
`requirements-ci.txt`, Python 3.10 or 3.13, and the matching `ci-...` output
name for a CI lock.
