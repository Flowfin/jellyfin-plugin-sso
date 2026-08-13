#!/usr/bin/env python3
"""Release-leg VEX gate (#1093).

Every release leg that ships the CycloneDX SBOM also ships the committed OpenVEX
document, so a consumer never gets this build's component list without the
dispositions that say which of its advisories are not exploitable here.

Nothing in a workflow file makes that true by itself. A leg is copied from its
neighbour when a new channel is opened, and the line that is easiest to forget is
the one that ships a side-document nobody sees until a scanner joins the two. So
the leg set is DERIVED rather than listed: any workflow that writes
`sbom.cyclonedx.sha256` is a leg shipping the SBOM, and is held to the rest.

What it refuses, and the failure each one prevents:

* the document missing from the path the legs name - a moved or deleted file
  turns four green releases into four releases that quietly stopped carrying
  their dispositions;
* a leg that ships the SBOM and never places the VEX document, by copy or by
  artifact - the leg publishes half the supply-chain pair;
* a leg that places it and emits no `openvex.sha256` - the asset ships with no
  integrity value, and the sha256 line is also the run-time proof the document
  reached the staging dir, since `sha256sum` on a missing file reds the step
  under `bash -e`;
* an `.md5` emitted for the VEX. Only the plugin zip may carry one. The manifest
  generator this repo replaced kept the LAST asset ending in `.md5` with no
  pairing, which is how the SBOM's checksum was published as the plugin's and
  broke every install (#942). A second `.md5` is that class reopened;
* a leg downloading the `vex-artifact` no job uploads - a rename on one side of
  that pair fails the release at its last step, after the build.

Fail-closed: anything unreadable is an error, not a pass.

Usage: check-release-vex.py [<repo-root>]
"""

import re
import sys
from pathlib import Path

# The committed document. The legs name this path; so does this gate, and a move
# that updates one and not the other is what the first check below catches.
VEX_SOURCE = Path("security/vex/openvex.json")

# Written by a leg that stages the SBOM as a release asset. This string is the
# subject derivation, not a formatting choice: it is what makes a new leg a leg.
SBOM_MARKER = "sbom.cyclonedx.sha256"

# One of these places the document in the staging dir the release uploads from.
PLACEMENTS = (f"cp {VEX_SOURCE.as_posix()}", "name: vex-artifact")

VEX_CHECKSUM = "openvex.sha256"

# Any of these would give the VEX an md5 sidecar, which is the #942 class.
FORBIDDEN_MD5 = ("openvex.md5", "md5sum openvex")

DOWNLOAD_MARKER = "download-artifact"
UPLOAD_MARKER = "upload-artifact"

# The artifact name, matched as a WHOLE yaml value rather than as a substring. A
# rename to `vex-artifacts` is the near-miss this exists for, and `"vex-artifact"
# in text` reads that as a match on both sides of the pair - the first draft of
# this gate did, and passed a mutation that renamed the upload and not the
# download.
ARTIFACT_LINE = re.compile(r"^\s*name:\s*vex-artifact\s*$")
USES_LINE = re.compile(r"^\s*(?:-\s*)?uses:\s*(\S+)")


def fail(message):
    print(f"::error::{message}", file=sys.stderr)
    sys.exit(1)


def workflow_texts(root):
    """Every workflow file, read once, as (path, text) pairs."""
    directory = root / ".github" / "workflows"
    if not directory.is_dir():
        fail(f"no workflow directory at {directory}")

    files = sorted(p for p in directory.iterdir() if p.suffix in (".yml", ".yaml"))
    if not files:
        fail(f"no workflow files under {directory}")

    texts = []
    for path in files:
        try:
            texts.append((path, path.read_text(encoding="utf-8")))
        except OSError as error:
            fail(f"cannot read {path}: {error}")
    return texts


def artifact_uses(path, text):
    """Which action each `name: vex-artifact` line belongs to, in this file.

    Read by walking the lines and remembering the most recent `uses:`, because a
    step's action and its `with: name:` are two lines of one block and the pair
    is what has to agree.
    """
    action = ""
    for line in text.splitlines():
        match = USES_LINE.match(line)
        if match:
            action = match.group(1)
        elif ARTIFACT_LINE.match(line):
            yield path, action


def check_artifact_pairing(texts):
    """A leg downloading `vex-artifact` needs a job somewhere that uploads it."""
    pairs = [pair for path, text in texts for pair in artifact_uses(path, text)]
    downloads = [path for path, action in pairs if DOWNLOAD_MARKER in action]
    uploads = [path for path, action in pairs if UPLOAD_MARKER in action]
    if downloads and not uploads:
        named = ", ".join(sorted({path.name for path in downloads}))
        fail(
            f"{named} downloads the vex-artifact, but no workflow uploads an artifact of "
            f"that exact name; a rename on one side of the pair fails the release at its "
            f"last step, after the build"
        )
    return uploads


def check_leg(path, text):
    name = path.name

    if not any(placement in text for placement in PLACEMENTS):
        fail(
            f"{name} ships the SBOM but never places {VEX_SOURCE.as_posix()}: "
            f"expected one of {' | '.join(PLACEMENTS)}"
        )

    # Checked before the sha256, so a leg that swapped one sidecar for the other is
    # refused for the reason that matters rather than for the missing sha256.
    for forbidden in FORBIDDEN_MD5:
        if forbidden in text:
            fail(
                f"{name} writes an md5 for the VEX ({forbidden!r}); only the plugin zip "
                f"may carry one, or the manifest can publish the wrong checksum (#942)"
            )

    if VEX_CHECKSUM not in text:
        fail(f"{name} ships the VEX document but writes no {VEX_CHECKSUM}")


def main(argv):
    root = Path(argv[1]) if len(argv) > 1 else Path.cwd()

    if not (root / VEX_SOURCE).is_file():
        fail(
            f"no VEX document at {(root / VEX_SOURCE).as_posix()}; the release legs copy "
            f"that path, so a release would ship the SBOM with no dispositions beside it"
        )

    texts = workflow_texts(root)
    uploads = check_artifact_pairing(texts)

    legs = [(p, t) for p, t in texts if SBOM_MARKER in t]
    if not legs:
        fail(
            f"no workflow writes {SBOM_MARKER}, so this gate has no subject; either the "
            f"release legs stopped shipping the SBOM or the marker moved"
        )

    for path, text in legs:
        check_leg(path, text)

    named = ", ".join(sorted(path.name for path, _ in legs))
    carriers = ", ".join(sorted(path.name for path in uploads))
    print(
        f"ok: {len(legs)} release leg(s) ship the OpenVEX document with a sha256 and no md5: "
        f"{named}" + (f" (artifact uploaded by {carriers})" if carriers else "")
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
