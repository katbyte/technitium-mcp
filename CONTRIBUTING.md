# Contributing

## Before sending a change

Run `make check-all`. It builds, runs the unit and live tests, and runs every check CI runs. It needs Docker.

A new tool or client method needs a live test. `make testacc` runs them on throwaway Technitium servers in Docker, and fails if one is missing. See [docs/development.md](docs/development.md).

## Releases

- Changes collect under "Unreleased" at the top of [CHANGELOG.md](CHANGELOG.md).
- A version is tagged when a batch is worth upgrading for, not for every change.
- Breaking changes are grouped into one release where possible, not shipped one per release.
- Pushing a `v*` tag builds and publishes the release.
