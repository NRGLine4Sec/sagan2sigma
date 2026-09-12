# lab

A locally built Sagan engine and the checks that pin down what it actually
does, so that this project's claims about Sagan's behaviour can be verified by
running the engine rather than by reading its C.

**Not part of the test suite, and CI never runs it.** A full pass starts several
hundred Sagan processes and takes the better part of an hour. What runs on every
change is `tests/`, which compares the conversion against a Python model of the
engine and against the real RSigma in seconds.

```sh
python lab/config/make-country-mmdb.py    # once, needs mmdb-writer and netaddr
lab/build/build-sagan.sh                  # once, clones and builds Sagan main
lab/run-all.sh                            # every check
lab/run-all.sh correlation                # one family, by filename substring
```

Two of the three engine builds need patches this repository does not carry, so
five of the sixteen check files and all three differentials skip themselves on a
fresh clone and say so.

**[docs/LAB.md](../docs/LAB.md) is the documentation**: what each check
establishes, what the differentials compare, the cost of a run, the fixtures,
and the traps that cost real time. Read it before writing a check.
