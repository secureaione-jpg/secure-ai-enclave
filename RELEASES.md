# Releases

Each release is a tag in this repository and the PCR0 its image measures to.
Build the tag with `enclave/scripts/build-reproducible.sh` (README) and
compare.

Built with: Amazon Linux 2023, Nitro CLI 1.5.0, Docker Buildx 0.19.3
(BuildKit is pinned inside the build script).

| Release | PCR0 | Status |
|---|---|---|
| `v32` | `02755a1197ec423a66be475b5b6ff8dad67a19bced3566ad6a7614fb4a9bd64e740bceb67af6fdbcd622bed4acc790b1` | Built twice from clean on 2026-11-13, same PCR0 both times; goes live once our app trusts it |

Earlier enclaves (v31 and before) were built before the build was
reproducible, so their PCR0 cannot be rebuilt from source.
