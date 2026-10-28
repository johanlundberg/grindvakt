remote := "origin"

# List available developer commands.
default:
    @just --list

# Run the normal locked test suite.
test:
    cargo test --locked

# Run ignored Redis integration tests against REDIS_URL, defaulting to localhost.
redis-test:
    REDIS_URL="${REDIS_URL:-redis://127.0.0.1/}" cargo test --locked --features redis --test redis_store -- --ignored --nocapture

# The v<version> tag triggers .github/workflows/publish.yml, which tests,
# publishes to crates.io and creates the GitHub release.
# Create and push a signed release tag, e.g. `just release 0.9.1`.
release version:
    #!/usr/bin/env bash
    set -euo pipefail
    version="{{ version }}"
    tag="v${version}"

    if ! [[ "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$ ]]; then
        echo "error: '${version}' is not a version like 1.2.3 or 1.2.3-rc.1" >&2
        exit 1
    fi

    if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
        echo "error: working tree has uncommitted changes" >&2
        exit 1
    fi

    # The tag must match the version that gets published (the workflow
    # refuses a mismatch too) and the one Cargo.lock pins.
    cargo_version="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)"
    lock_version="$(awk '/^name = "grindvakt"$/{getline; gsub(/[^0-9A-Za-z.-]/, ""); sub(/^version/, ""); print; exit}' Cargo.lock)"
    if [[ "${cargo_version}" != "${version}" || "${lock_version}" != "${version}" ]]; then
        echo "error: version mismatch: tag ${version}, Cargo.toml ${cargo_version}, Cargo.lock ${lock_version}" >&2
        exit 1
    fi

    if git rev-parse -q --verify "refs/tags/${tag}" >/dev/null; then
        echo "error: tag ${tag} already exists locally" >&2
        exit 1
    fi
    if git ls-remote --exit-code --tags {{ remote }} "refs/tags/${tag}" >/dev/null 2>&1; then
        echo "error: tag ${tag} already exists on {{ remote }}" >&2
        exit 1
    fi

    branch="$(git rev-parse --abbrev-ref HEAD)"
    echo "Tagging ${tag} on ${branch} ($(git rev-parse --short HEAD))"
    git tag --sign --message "Release ${tag}" "${tag}"
    git tag --verify "${tag}"
    git push {{ remote }} "${tag}"
    echo "Pushed ${tag} to {{ remote }}"
