"""Everything that names this tool on the wire, in one place.

A probe often has to send a value it can recognise again: an Origin the target
cannot have allow-listed, a marker it looks for in the response, a path that
certainly does not exist, a body field nothing should accept. Each of those
used to be a constant beside the probe that sent it, and between them they
spelled out the tool's name about twenty times over, in header names, in
paths, in query parameters and in request bodies.

They all come from here now, so a run cannot be half quiet.

Two modes:

``announced``
    The default. The User-Agent names Namazu and its repository, and every
    marker says "namazu". Both sides of an engagement can then tell which
    requests in a log were the test, which is usually what an authorised
    engagement wants, and a marker left in a database says plainly where it
    came from.

``quiet``
    The tool does not put its name on anything. The User-Agent is an ordinary
    browser string and every marker is derived from a token drawn fresh for the
    run. For testing whether a target's own monitoring notices a scan, and for
    the WAF that refuses an unfamiliar client by name before the test can
    start.

The quiet markers are random rather than a second fixed set on purpose: a
fixed alternative would be a Namazu fingerprint of its own the moment anyone
wrote it down.

What quiet mode does not do, and must not be sold as doing: it changes what
the traffic is called, not what it is. The same probes run in the same order,
a SQL injection payload still looks exactly like a SQL injection payload, and
two hundred requests to one endpoint still look like two hundred requests to
one endpoint. It defeats attribution to this tool, not detection of testing.
It also does not reach the external scanners, which announce themselves.

``describe`` gives a report the token, because a run that signs its markers
with a random string still has to be attributable afterwards: the operator
needs one value to search the target's logs and data for during cleanup.
"""
from __future__ import annotations

import secrets
import string
from dataclasses import dataclass, field

ANNOUNCED = "announced"
QUIET = "quiet"
MODES = (ANNOUNCED, QUIET)

# What the tool calls itself when it is not announcing itself. A common desktop
# browser, because an API behind a WAF is used to seeing one; an engagement that
# needs something else sets the user agent directly, which still wins over this.
BROWSER_USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")

# Hosts in .invalid never resolve (RFC 2606), which is what the probes that
# must not reach anything depend on. The suffix stays in both modes: a name
# that might resolve would turn a detection into a request to someone else's
# server, and that matters more than the suffix looking like a probe.
_ANNOUNCED_HOST = "namazu-probe.invalid"


def _token() -> str:
    """A run token that is safe everywhere a marker derived from it is sent.

    It begins with a letter because the markers reach places where a leading
    digit is not allowed: a GraphQL field name, a JSON property name, and the
    first label of a host name. A token that began with a digit would turn the
    GraphQL suggestion probe into a syntax error and quietly disable the check
    for most runs, which is the failure a stealth mode is most likely to hide.
    """
    return secrets.choice(string.ascii_lowercase) + secrets.token_hex(4)


@dataclass(frozen=True)
class Signature:
    """What one audit puts its name on. One instance per run.

    One instance, because probes compare across requests: a control and its
    probe have to carry the same marker, and two instances would draw two
    tokens and quietly stop matching.
    """

    quiet: bool = False
    token: str = field(default_factory=_token)

    @property
    def stem(self) -> str:
        """The word every marker is built from."""
        return self.token if self.quiet else "namazu"

    @property
    def user_agent(self) -> str | None:
        """The User-Agent to use when the operator set none, or None for the default."""
        return BROWSER_USER_AGENT if self.quiet else None

    @property
    def host(self) -> str:
        """A host name that resolves nowhere, for a probe that must not reach anything."""
        return f"{self.token}.invalid" if self.quiet else _ANNOUNCED_HOST

    @property
    def origin(self) -> str:
        """An Origin the target cannot legitimately have allow-listed."""
        return f"https://{self.host}"

    def marker(self, suffix: str = "") -> str:
        """A value a probe sends and then looks for coming back."""
        return f"{self.stem}{suffix}"

    def header(self, suffix: str) -> str:
        """A request header name no application has a use for."""
        return f"X-Namazu-{suffix}" if not self.quiet else f"X-{self.token}-{suffix}"

    def slug(self, suffix: str = "") -> str:
        """A path or parameter name, for a URL rather than a body."""
        return f"{self.stem}-{suffix}" if suffix else self.stem

    @property
    def field_name(self) -> str:
        """A body property the target's schema does not declare."""
        return f"x_{self.token}" if self.quiet else "namazu_probe_marker"

    @property
    def invalid_token(self) -> str:
        """A bearer credential that is structurally wrong, not merely unknown."""
        return f"{self.stem}.invalid.credential"

    def describe(self) -> str:
        """A report line, empty unless the run has something to disclose."""
        if not self.quiet:
            return ""
        return (
            "Requests did not identify Namazu: the User-Agent was an ordinary browser string, and "
            f"every probe marker, header and path was derived from the token {self.token}. Search "
            "the target's logs and stored data for that token to attribute this run. The probes "
            "themselves were unchanged, so the traffic is still recognisable as a security test."
        )


def mode_of(name: str) -> bool:
    """Whether a mode name means quiet. Anything unrecognised announces."""
    return str(name or "").strip().lower() == QUIET
