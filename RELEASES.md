# Releases

Each release is a tag in this repository and the PCR0 its image measures to.
Build the tag with `enclave/scripts/build-reproducible.sh` (README) and
compare.

Built with: Amazon Linux 2023, Nitro CLI 1.5.0, Docker Buildx 0.19.3
(BuildKit is pinned inside the build script).

| Release | PCR0 | Status |
|---|---|---|
| `v33` | `edd94d281994498fecdee26a9dd0de8d3ad2e6b4acc721c70783f96b6232d571bc37908b2b7c0555c6217360710648fe` | Built 2026-11-15 from main at 4627f0d4; live |
| `v32` | `02755a1197ec423a66be475b5b6ff8dad67a19bced3566ad6a7614fb4a9bd64e740bceb67af6fdbcd622bed4acc790b1` | Built twice from clean on 2026-11-13, same PCR0 both times; never served, replaced by v33 |

Earlier enclaves (v31 and before) were built before the build was
reproducible, so their PCR0 cannot be rebuilt from source.
