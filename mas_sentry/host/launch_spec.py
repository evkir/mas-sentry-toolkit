# SPDX-License-Identifier: AGPL-3.0-or-later
"""Report a server whose launch spec does not name the code it will run.

A server declared as `npx -y pkg` or `uvx pkg` is fetched from a registry every
time the host starts it. With no version in the spec, which release executes is
settled by whoever can publish the package and by the state of the machine, not
by the operator's declaration - the rug-pull surface CWE-494 names. An exact
version is the one shape that forecloses it.

The verdict is a claim about two resolvers' documented behaviour, so both are
cited rather than assumed:

- npx takes a spec positionally (`npx -- pkg@1.2.3`) or through
  `--package`/`-p`. Without a specifier npm matches "whatever version exists in
  the local project", so an absent pin means the executed release follows
  machine state rather than the config.
  https://docs.npmjs.com/cli/v10/commands/npx
- uvx accepts `pkg@1.2.3` and `pkg@latest` only: "the `@` syntax cannot be used
  for anything other than an exact version". Ranges and comparators live in
  `--from 'pkg==1.2.3'`, which is why `--from` is read here as a first-class
  source of a pin and not as an opaque flag.
  https://docs.astral.sh/uv/guides/tools/

Four cases are deliberately silent, and each is a false positive this module
would otherwise produce:

- An exact version, however it was supplied. A check an operator cannot pass by
  doing it right is a false-positive generator (R-2.4).
- A command that resolves nothing at launch: an absolute path, `python`,
  `node`, `docker`. There is no registry lookup to pin, so there is no pin to
  demand. `docker run img:latest` is the same weakness through a different
  mechanism and belongs wherever images are audited, not here.
- A remote server, which carries a `url` and no command: nothing is launched on
  this host at all.
- A pin given through `--from`, which is the documented way to express one for
  uvx. Firing on it would punish the correct form.

Scope decides how bad it is, not whether it is true, the same way it does for a
committed credential: a repository spec arrives with every checkout and picks
code for everyone who clones it, while the same spec in a user-scope file is
the operator's own exposure and nobody else's.

One bound is accepted knowingly. A spec is found by scanning args for the
options above and otherwise taking the first non-flag argument, so an unknown
option that takes a separate value could let its value be read as the package.
The `=` form is unambiguous and the two resolvers' own value-taking options are
handled by name; anything further would need a table of every flag npx and uv
accept, which would drift faster than it would help.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from mas_sentry.core.finding import Finding, Severity

from .inventory import Inventory, ServerEntry

_RESOLVERS: Final = frozenset({"npx", "uvx"})

# Options that carry the package spec in a separate argument or after `=`.
_VALUE_OPTIONS: Final = {"npx": ("--package", "-p"), "uvx": ("--from",)}

# A version starts with a digit, optionally behind a `v`. Anything else after
# `@` is a dist-tag - `latest`, `next`, `beta` - which names a moving target
# rather than a release: uv documents `@` as exact-version-or-latest, and npm
# resolves a tag afresh at every launch.
_VERSION = re.compile(r"^v?\d")

# PEP 508 operators that admit more than one release. A bare `==` is a pin; a
# range, a negation or a wildcard is not.
_LOOSE_SPECIFIER = re.compile(r"[><~!*,]")


@dataclass(frozen=True, slots=True)
class PinVerdict:
    """What a launch spec says about the release it will run.

    `pin` is `exact`, `moving` (a dist-tag or a range) or `absent`. The spec
    itself is not kept: a verdict re-derivable from the resolver, where the
    spec was found and the pin form needs no config value in the report, so
    the guarantee sits in the type rather than in a filter (R-7.3).
    """

    resolver: str
    origin: str
    pin: str


def _basename(command: str) -> str:
    """The command's final segment, for a config that spells out a full path.

    Both separators are folded because a config is audited on whatever machine
    the responder is sitting at, which is not necessarily the one that wrote it.
    """
    return command.replace("\\", "/").rsplit("/", 1)[-1].lower().removesuffix(".exe")


def _spec_of(resolver: str, args: tuple[str, ...]) -> tuple[str, str] | None:
    """The package spec and where it was found, or None when the args name none.

    An explicit option wins over a positional argument, because that is the
    resolver's own precedence: `uvx pkg --from other==1.0` installs `other`.
    """
    options = _VALUE_OPTIONS[resolver]
    pending: str | None = None
    positional: str | None = None
    for arg in args:
        if pending is not None:
            return arg, pending
        if arg in options:
            pending = arg
        elif (prefixed := next((o for o in options if arg.startswith(f"{o}=")), None)) is not None:
            return arg.split("=", 1)[1], prefixed
        elif positional is None and arg != "--" and not arg.startswith("-"):
            positional = arg
    return (positional, "positional") if positional is not None else None


def _pin_of(spec: str, origin: str) -> str:
    """Classify what the spec pins, by the syntax the origin option accepts."""
    if origin == "--from":
        if _LOOSE_SPECIFIER.search(spec):
            return "moving"
        return "exact" if "==" in spec else "absent"
    # `@` at the front is a scope, not a separator: `@scope/pkg` pins nothing,
    # while `@scope/pkg@1.2.3` does, so the last `@` is the one that matters.
    at = spec.rfind("@")
    if at <= 0:
        return "absent"
    return "exact" if _VERSION.match(spec[at + 1 :]) else "moving"


def verdict_for(entry: ServerEntry) -> PinVerdict | None:
    """The pin verdict for one server, or None when nothing is resolved at launch."""
    if entry.command is None:
        return None
    resolver = _basename(entry.command)
    if resolver not in _RESOLVERS:
        return None
    found = _spec_of(resolver, entry.args)
    if found is None:
        return None
    spec, origin = found
    return PinVerdict(resolver=resolver, origin=origin, pin=_pin_of(spec, origin))


def _unpinned_finding(inv: Inventory, server: ServerEntry, verdict: PinVerdict) -> Finding:
    src = inv.source
    committed = src.scope == "project"
    observed = (
        "names a dist-tag or a version range, which resolves afresh at every launch"
        if verdict.pin == "moving"
        else "carries no version at all"
    )
    consequence = (
        "The file arrives with a checkout, so this chooses code for everyone who clones the repository"
        if committed
        else "The file is the operator's own, so the exposure is theirs rather than anyone else's"
    )
    return Finding(
        module="host.server_unpinned",
        title=f"{src.host} ({src.scope}): {server.name} is launched from an unpinned {verdict.resolver} spec",
        detail=(
            f"{src.path} starts {server.name} with {verdict.resolver}, and the spec found at "
            f"{verdict.origin} {observed}. Which release runs is therefore decided by whoever can publish "
            f"the package, not by this config. {consequence}. The spec itself is not read into this report - "
            "only the resolver, where the spec was found and whether it pins a release"
        ),
        severity=Severity.MEDIUM if committed else Severity.LOW,
        target=str(src.path),
        tags=["host", "server_unpinned"],
        evidence={
            "server": server.name,
            "resolver": verdict.resolver,
            "spec_origin": verdict.origin,
            "observed_pin": verdict.pin,
            "accepted_pin": "exact",
        },
    )


def launch_findings(inv: Inventory) -> list[Finding]:
    """One row per server whose launch spec does not pin a release."""
    return [
        _unpinned_finding(inv, server, verdict)
        for server in inv.servers
        if (verdict := verdict_for(server)) is not None and verdict.pin != "exact"
    ]
