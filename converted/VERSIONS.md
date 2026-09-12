# Converted rule set versions

This table records each iteration of the converted rule sets, newest first,
produced from
[`quadrantsec/sagan-rules`](https://github.com/quadrantsec/sagan-rules) so they
can be used without installing this project. Both profiles are refreshed
together whenever the upstream corpus changes; see
`.github/workflows/convert-rules.yml`. The default `rsigma-syslog` snapshot is
under [`converted/`](rules); the `vector-enriched` one, which recovers more,
is [`converted-vector-enriched/`](../converted-vector-enriched).

The **version** is the short hash of the `sagan-rules` commit and the
`sagan2sigma` commit the rules were produced from, so it is reproducible. The
**sagan-rules date** is that commit's date, which is how old the rules are.

| Version | sagan-rules commit | sagan-rules date | sagan2sigma | Generated | Default | Enriched |
| --- | --- | --- | --- | --- | ---: | ---: |
| `d62daa240aea` | [`8d65d8a91723`](https://github.com/quadrantsec/sagan-rules/commit/8d65d8a917234df5970223dc32df6af8ce8d2e49) | 2026-09-11 | `2eb2f73cc6cd` | 2026-09-12 | 8714 / 10025 (86.9%) | 9464 / 10025 (94.4%) |
| `d2f53c1a0cfc` | [`cab835cc4ac1`](https://github.com/quadrantsec/sagan-rules/commit/cab835cc4ac1ed379788b2cab549a39e4e92d432) | 2026-09-09 | `d61bc86dc517` | 2026-09-11 | 8683 / 10025 (86.6%) | 9464 / 10025 (94.4%) |
| `3947235013a9` | [`cab835cc4ac1`](https://github.com/quadrantsec/sagan-rules/commit/cab835cc4ac1ed379788b2cab549a39e4e92d432) | 2026-09-09 | `d370eff0a263` | 2026-09-10 | 8679 / 10025 (86.6%) | 9434 / 10025 (94.1%) |
| `bb220a236953` | [`c6fddfda44ce`](https://github.com/quadrantsec/sagan-rules/commit/c6fddfda44cef201bb905761a8474f0453393252) | 2026-09-04 | `1fe3f42f9359` | 2026-09-08 | 8679 / 10026 (86.6%) | 9433 / 10026 (94.1%) |
| `0a2b7f74a95e` | [`c6fddfda44ce`](https://github.com/quadrantsec/sagan-rules/commit/c6fddfda44cef201bb905761a8474f0453393252) | 2026-09-04 | `4b10d6cfc90e` | 2026-09-07 | 8679 / 10026 (86.6%) | 9433 / 10026 (94.1%) |
| `4829898a876e` | [`c6fddfda44ce`](https://github.com/quadrantsec/sagan-rules/commit/c6fddfda44cef201bb905761a8474f0453393252) | 2026-09-04 | `91ce46a8ca3a` | 2026-09-05 | 8679 / 10026 (86.6%) | 9433 / 10026 (94.1%) |
| `9fa397946702` | [`27f7c0f8c328`](https://github.com/quadrantsec/sagan-rules/commit/27f7c0f8c328f770b8b8deb2c753f8fce84d416d) | 2026-09-02 | `dad3549950de` | 2026-09-03 | 8678 / 10025 (86.6%) | 9432 / 10025 (94.1%) |
| `bbcbd0f5336a` | [`09297fd813c1`](https://github.com/quadrantsec/sagan-rules/commit/09297fd813c1091da4cb8ca96b0bc41c6af9476a) | 2026-08-31 | `6738358a0874` | 2026-09-01 | 8675 / 10022 (86.6%) | 9429 / 10022 (94.1%) |
| `327a5fefbf2e` | [`4e3ef54ecd81`](https://github.com/quadrantsec/sagan-rules/commit/4e3ef54ecd81a68c1ace00ef21f4cb7c78ed2b8e) | 2026-08-28 | `075308ee3e92` | 2026-08-29 | 8674 / 10021 (86.6%) | 9428 / 10021 (94.1%) |
| `f771f128b5f3` | [`78cd4495429b`](https://github.com/quadrantsec/sagan-rules/commit/78cd4495429b927592dec94970ac356f92416b31) | 2026-08-27 | `6dec43aec8b2` | 2026-08-28 | 8674 / 10017 (86.6%) | 9424 / 10017 (94.1%) |
| `effe446ac341` | [`b99ecfc2d0dc`](https://github.com/quadrantsec/sagan-rules/commit/b99ecfc2d0dc3e2c5507f49e5be338a03b440ae4) | 2026-08-26 | `75732512e78b` | 2026-08-27 | 8674 / 10017 (86.6%) | 9424 / 10017 (94.1%) |
| `641b5e6c2cff` | [`0ff6289d621d`](https://github.com/quadrantsec/sagan-rules/commit/0ff6289d621dcc4fe81b99f9b8ba7e824067e07d) | 2026-08-20 | `10cb852be08a` | 2026-08-25 | 8676 / 10018 (86.6%) | 9425 / 10018 (94.1%) |
| `8229b90d847f` | [`0ff6289d621d`](https://github.com/quadrantsec/sagan-rules/commit/0ff6289d621dcc4fe81b99f9b8ba7e824067e07d) | 2026-08-20 | `bdbcadfbee5c` | 2026-08-24 | 8676 / 10018 (86.6%) | 9425 / 10018 (94.1%) |
| `2e81b7799349` | [`0ff6289d621d`](https://github.com/quadrantsec/sagan-rules/commit/0ff6289d621dcc4fe81b99f9b8ba7e824067e07d) | 2026-08-20 | `c4c2b1b837cc` | 2026-08-23 | 8676 / 10018 (86.6%) | 9425 / 10018 (94.1%) |
| `abe26c99fc1b` | [`0ff6289d621d`](https://github.com/quadrantsec/sagan-rules/commit/0ff6289d621dcc4fe81b99f9b8ba7e824067e07d) | 2026-08-20 | `9676858a727f` | 2026-08-22 | 8677 / 10018 (86.6%) | 9426 / 10018 (94.1%) |
| `c4bf97dbe818` | [`0ff6289d621d`](https://github.com/quadrantsec/sagan-rules/commit/0ff6289d621dcc4fe81b99f9b8ba7e824067e07d) | 2026-08-20 | `277b3d1d6d2d` | 2026-08-21 | 8680 / 10018 (86.6%) | 9427 / 10018 (94.1%) |
| `31ffd67138cd` | [`9e3bad5e0871`](https://github.com/quadrantsec/sagan-rules/commit/9e3bad5e0871672edd7f2016cfd87738b54b3b45) | 2026-08-18 | `6a9154141576` | 2026-08-19 | 8680 / 10018 (86.6%) | 9427 / 10018 (94.1%) |
| `481f5733b19f` | [`9dc7b1f7603b`](https://github.com/quadrantsec/sagan-rules/commit/9dc7b1f7603b92ac260205a1ac951bea6297f10d) | 2026-08-14 | `636d06b9bec7` | 2026-08-17 | 8680 / 10019 (86.6%) | 9428 / 10019 (94.1%) |
| `3b2179a2c273` | [`9dc7b1f7603b`](https://github.com/quadrantsec/sagan-rules/commit/9dc7b1f7603b92ac260205a1ac951bea6297f10d) | 2026-08-14 | `d3d9c543a98d` | 2026-08-15 | 8671 / 10019 (86.5%) | 9280 / 10019 (92.6%) |
| `554db0e28946` | [`44d11446d16c`](https://github.com/quadrantsec/sagan-rules/commit/44d11446d16c1430d125c81a23ca4a3f0f5080c9) | 2026-08-07 | `2c13d4316bce` | 2026-08-14 | 8659 / 9997 (86.6%) | 9265 / 9997 (92.7%) |
| `8e0b793f259d` | [`44d11446d16c`](https://github.com/quadrantsec/sagan-rules/commit/44d11446d16c1430d125c81a23ca4a3f0f5080c9) | 2026-08-07 | `295f05c0d2d2` | 2026-08-10 | 8659 / 9997 (86.6%) | 9010 / 9997 (90.1%) |
