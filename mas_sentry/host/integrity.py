# SPDX-License-Identifier: AGPL-3.0-or-later
"""Report a config the operator is not the only one able to change.

The file decides what the host executes, so whoever can rewrite it has code
execution at the next start. Two CVEs in the 2026 corpus are this:

- CVE-2025-54136 ("MCPoison") - a config another writer rewrites after the user
  approved it, which turns one approval into the attacker's persistence.
- CVE-2026-50549 ("DuneSlide") - a config path that canonicalises somewhere
  other than where it appears to be.

`discovery.py` reads the bits; this module decides which combination of them is
an exposure (R-1.7). There are three observations and two rows, because two of
the observations end in the same place by different means:

- write permission for others on the file: the content can be rewritten in place
  (CWE-732);
- write permission for others on the directory, with no sticky bit: the file can
  be replaced wholesale, which POSIX treats as a property of the directory and
  not of the file (CWE-732, same outcome);
- a path that arrives somewhere else: what runs is not what the location appears
  to hold (CWE-59).
https://man7.org/linux/man-pages/man2/unlink.2.html

The first two share one check name because the remedy is the same kind of thing
and the outcome is identical; the row names which object is open and which bit
made it so, because a verdict a reviewer cannot re-derive is not deterministic
(R-7.2). The third is its own check: the CWE differs and so does the fix - a
mode is corrected with chmod, a redirection by putting the file back.

What this module deliberately refuses to say:

- Nothing about group-writability. Whether `g+w` reaches anybody else depends on
  who is in the group; no vendor documents the membership of the macOS `staff`
  group, and `grp` omits users whose primary group it is, which is that case
  exactly. The bits are in the evidence and no claim is made about them (R-2.13).
- Nothing about a world-writable directory that carries the sticky bit. `/tmp`
  is 1777 and no user can replace another's file there, so firing would be a
  false positive on every config under a directory shaped like it (R-2.4).
- Nothing about a config owned by somebody other than the auditor. The command
  takes `--home`, so a responder reading a mounted image or another account owns
  none of it, and an owner mismatch there is the normal case rather than a
  finding. It travels in the evidence to explain the rest.
- Nothing at all when the permissions could not be read - Windows, a broken
  link, a directory that cannot be traversed. An unassessed surface is not a
  clean one, and the inventory row already carries the absence (R-2.1).

Severity does not follow scope the way a committed credential's does. A key in a
repository file is worse than one in the operator's own because the repository
publishes it; a writable config is the same weakness wherever it sits, since the
machine that reads it is this one either way. Redirection is the exception: a
symlinked config under the operator's home is ordinary - every dotfile manager
produces them - while a repository that ships one chose that destination for
whoever clones it.
"""

from __future__ import annotations

import stat

from mas_sentry.core.finding import Finding, Severity

from .discovery import HostConfig, PathExposure

_ACCEPTED_MODE = "no write permission for others on the file, and none on its directory unless the sticky bit is set"


def _open_routes(exposure: PathExposure) -> tuple[str, ...]:
    """Which objects let somebody other than the owner change what the host reads."""
    routes = []
    if exposure.mode & stat.S_IWOTH:
        routes.append("file")
    if exposure.dir_mode & stat.S_IWOTH and not exposure.dir_mode & stat.S_ISVTX:
        routes.append("directory")
    return tuple(routes)


def _writable_finding(src: HostConfig, exposure: PathExposure, routes: tuple[str, ...]) -> Finding:
    observed = {
        ("file",): f"its mode is {exposure.mode:04o}, which grants write permission to any local user",
        ("directory",): (
            f"the directory holding it is {exposure.dir_mode:04o} with no sticky bit, so the file can be "
            "replaced wholesale even though its own mode is restrictive"
        ),
        ("file", "directory"): (
            f"its mode is {exposure.mode:04o} and the directory holding it is {exposure.dir_mode:04o} with no "
            "sticky bit, so it can be rewritten in place or replaced outright"
        ),
    }[routes]
    return Finding(
        module="host.config_writable",
        title=f"{src.host} ({src.scope}): config can be changed by a user other than its owner",
        detail=(
            f"{src.path} decides what this host executes, and {observed}. Anyone who can change it has code "
            "execution the next time the host starts, and an approval the operator already gave carries over "
            "to whatever replaces it - the persistence CVE-2025-54136 describes. Expected: "
            f"{_ACCEPTED_MODE}"
        ),
        severity=Severity.HIGH,
        target=str(src.path),
        tags=["host", "config_writable"],
        evidence={
            "routes": list(routes),
            "observed_mode": f"{exposure.mode:04o}",
            "observed_dir_mode": f"{exposure.dir_mode:04o}",
            "dir_sticky": bool(exposure.dir_mode & stat.S_ISVTX),
            "owned_by_auditor": exposure.owned_by_auditor,
            "accepted": _ACCEPTED_MODE,
        },
    )


def _redirected_finding(src: HostConfig) -> Finding:
    committed = src.scope == "project"
    consequence = (
        "The repository chose that destination for everyone who clones it, and the file that runs is outside "
        "the tree a reviewer reads"
        if committed
        else "A dotfile manager is the ordinary reason for this, so the question is whether the destination is "
        "one the operator chose"
    )
    return Finding(
        module="host.config_redirected",
        title=f"{src.host} ({src.scope}): config path resolves outside its expected location",
        detail=(
            f"{src.path} is read by this host, and it canonicalises to {src.resolved}, which is not where the "
            f"documented location puts it. {consequence}. This is the shape CVE-2026-50549 turns on: what the "
            "path appears to hold and what it arrives at are different files. Expected: the documented "
            "location, or a destination the operator can account for"
        ),
        severity=Severity.MEDIUM if committed else Severity.LOW,
        target=str(src.path),
        tags=["host", "config_redirected"],
        evidence={
            "declared_path": str(src.path),
            "resolved_path": str(src.resolved),
            "scope": src.scope,
        },
    )


def integrity_findings(src: HostConfig) -> list[Finding]:
    """Rows about the config file itself, as opposed to what it declares."""
    out: list[Finding] = []
    if src.exposure is not None:
        routes = _open_routes(src.exposure)
        if routes:
            out.append(_writable_finding(src, src.exposure, routes))
    if src.via_symlink:
        out.append(_redirected_finding(src))
    return out
