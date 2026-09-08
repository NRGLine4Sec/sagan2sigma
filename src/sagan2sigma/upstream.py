"""Upstream rules that do not do what they say, in Sagan.

Every other part of this tool asks whether the *conversion* is faithful. This
one asks something the conversion cannot: whether the rule it started from
works at all in the engine it was written for.

The question is not academic. 764 corpus rules fall into the silent category
below, and a migration that converts them faithfully inherits rules that never
fired. Someone comparing the converted output against a running Sagan would find
them agreeing perfectly, both silent, and conclude the conversion was sound.
Five more load and fire while grouping on fewer keys than they name, two stop
the engine from starting, one asserts what it means to forbid, and one carries
an exclusion that can never exclude anything.

Each detector below corresponds to an engine behaviour established by running a
locally built Sagan, not by reading it. The comments name what was measured, so
that a reader can disagree with the conclusion rather than with an assertion.
That matters most where the syntax looks decisive and is not: an unbalanced `|`
is harmless in two of its shapes and fatal in the rest, and only the engine
says which is which.

Most have a fix upstream, proposed as pull requests against
`quadrantsec/sagan-rules`. Two do not, both being engine defects rather than
rule ones: `pcre:!` has no negation to fix in the rules, and a key path clipped
above the level that names the value cannot be written any other way.

What this deliberately does **not** do is judge intent. A rule can load, fire,
and still be useless because its pattern matches nothing any real appliance
emits. Nothing here can see that, and nothing in this repository can.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from .sagan.model import SaganRule


class DefectCode(str, Enum):
    """Why an upstream rule does not behave as written."""

    #: The engine refuses the ruleset, so Sagan does not start.
    WILL_NOT_LOAD = "U_WILL_NOT_LOAD"
    #: The rule loads and can never match.
    CANNOT_MATCH = "U_CANNOT_MATCH"
    #: The rule loads and matches, but groups on fewer keys than it names.
    WRONG_GROUPING = "U_WRONG_GROUPING"
    #: The rule loads and matches, but the condition means its opposite.
    INVERTED_CONDITION = "U_INVERTED_CONDITION"
    #: The rule loads and matches, but one condition can never bite, so the
    #: rule is broader than it reads.
    INERT_CONDITION = "U_INERT_CONDITION"


@dataclass(frozen=True, slots=True)
class UpstreamDefect:
    """One rule that does not do what it says, and why."""

    sid: str
    source_file: str
    code: DefectCode
    detail: str


#: Tracking keys the `after` parser recognises. Each is compared with an exact
#: strcmp, so a near miss contributes nothing. Measured: two events differing
#: only in an unrecognised key share a counter.
AFTER_KEYS = frozenset({"by_src", "by_dst", "by_username", "by_srcport", "by_dstport"})

#: `by_string` is a special case: inert under `after` but honoured by
#: `threshold`, so a rule tracking it alone is not necessarily dead.
AFTER_INERT_BUT_COUNTED = frozenset({"by_string"})

#: The longest JSON key path the parser can store. `JSON_MAX_KEY_SIZE` is 32 in
#: `src/sagan-defs.h` and the path is terminated early, so anything longer is
#: kept truncated and a rule naming the full path compares against a name that
#: was never stored. Measured to the character: 30 matches, 31 does not.
MAX_JSON_KEY = 30

#: The options whose values Sagan expands with `Content_Pipe`, turning `|3a|`
#: into a byte. `src/rules.c` calls it from lines 1942 and 1962 for
#: `meta_content`, 2202 for `json_content`, 2500 for `json_meta_content` and
#: 2828 for `content`.
PIPE_EXPANDED = frozenset(
    {"content", "meta_content", "json_content", "json_meta_content"}
)

_HEX = frozenset("0123456789abcdefABCDEF")
_TRACK = re.compile(r"track\s+([a-z_&]+)", re.I)
_JSON_KEY = re.compile(r'json_(?:meta_)?content\s*:\s*!?\s*"\.([A-Za-z0-9_.\[\]@-]+)"')
_JSON_PCRE_KEY = re.compile(r'json_pcre\s*:\s*!?\s*"\.([A-Za-z0-9_.\[\]@-]+)"')
_QUOTED = re.compile(r'"([^"]*)"')


#: Options whose argument is a single quoted string. Anything after the closing
#: quote means a `;` was forgotten and the next option was swallowed into this
#: one. Measured: the rule loads without complaint and then matches nothing at
#: all, not even a message holding the quoted text, and the same happens
#: whatever the swallowed text is.
_SINGLE_QUOTED = frozenset({"content", "program"})
_QUOTED_ARGUMENT = re.compile(r'^\s*!?\s*"([^"]*)"(.*)$', re.S)

#: Header protocols an event arriving through syslog can satisfy on its own.
#: Measured: `any`, `udp` and `syslog` match, `tcp` and `icmp` do not, and
#: `default_proto` is what supplies the protocol for the rest.
SYSLOG_PROTOCOLS = frozenset({"any", "udp", "syslog"})

#: A port slot the engine actually enforces: a number, or a variable named for
#: a port. Anything else there is not a port at all and does not constrain
#: matching, which is worth stating because the corpus puts other things there:
#: `alert any $EXTERNAL_NET any -> any $HOME_NET` leaves an address variable in
#: the port slot, and such rules match normally. Measured: `21`, `$FTP_PORT`
#: and `$HTTP_PORT` each stop a syslog event from matching, `$HOME_NET` does
#: not. Flagging on "not any" instead reported 22 rules, 14 of them healthy.
_PORT_SLOT = re.compile(r"^(?:\d+|\$[A-Za-z0-9_]*PORTS?)$", re.I)


def _enforced_port(slot: str) -> bool:
    """Whether this header port slot is one the engine will hold an event to."""
    return bool(_PORT_SLOT.match(slot.strip()))


#: The two keywords taking a comma-separated list of values rather than one
#: quoted argument. Their items are read verbatim, quotes included.
_VALUE_LISTS = ("meta_content", "json_meta_content")


@dataclass(frozen=True, slots=True)
class _ValueList:
    """One `meta_content` or `json_meta_content` option's value list."""

    keyword: str
    negated: bool
    quoted: tuple[str, ...]
    total: int


def _quoted_items(rule: SaganRule) -> list[_ValueList]:
    """List items a rule wrapped in quotes, with their keyword and negation.

    `content` and `json_content` take a quoted argument and the quotes delimit
    it. The two list keywords do not: the value list is split on commas and each
    item is compared as it stands, so quotes around an item are part of the
    text being searched for.

    Measured on the engine, `meta_content` and `json_meta_content` alike:
    `json_meta_content:".eventtype","analytics"` matches an event whose value is
    the six-character `"analytics"` with its quotes, and does not match
    `analytics`; the same rule without the quotes matches `analytics` and not
    the quoted form. A quoted item in a list therefore searches for something a
    JSON or syslog producer does not emit.
    """
    found: list[_ValueList] = []
    for keyword in _VALUE_LISTS:
        for option in rule.iter_options(keyword):
            if not option.value:
                continue
            text = option.value.lstrip()
            negated = text.startswith("!")
            # Both keywords put their key or template first, quoted for
            # meta_content and usually quoted for json_meta_content, so the
            # list starts after the first comma.
            _, comma, rest = text.partition(",")
            if not comma:
                continue
            items = [part.strip() for part in rest.split(",") if part.strip()]
            quoted = tuple(
                item
                for item in items
                if len(item) >= 2 and item[0] == '"' and item[-1] == '"'
            )
            if quoted:
                found.append(_ValueList(keyword, negated, quoted, len(items)))
    return found


def _piped_values(rule: SaganRule) -> list[tuple[str, str]]:
    """Every string handed to `Content_Pipe`, with the option carrying it."""
    values: list[tuple[str, str]] = []
    for option in rule.options:
        if option.name not in PIPE_EXPANDED or not option.value:
            continue
        if option.name == "meta_content":
            # The quoted helper is expanded on its own, and the whole
            # comma-separated remainder is expanded as one string *before* it
            # is split, so an unterminated pipe anywhere in the list counts.
            helper, comma, rest = option.value.partition(",")
            quoted = _QUOTED.search(helper)
            if quoted:
                values.append((option.name, quoted.group(1)))
            if comma:
                values.append((option.name, rest))
        else:
            values.extend((option.name, v) for v in _QUOTED.findall(option.value))
    return values


def _unterminated_hex(value: str) -> tuple[DefectCode, str] | None:
    """How the engine ends up reading a value whose hex section never closes.

    `Content_Pipe` sets a flag on the first `|` and clears it only on finding a
    closing `|` three characters later. Until then it takes the next two
    characters as a hex pair on every pass, with nothing checking that the
    sequence was closed before the value ran out. What that produces depends on
    what is left, and only one of the outcomes is loud:

    ==================  ==========================================
    ``alpha|``          matches; the trailing pipe adds nothing
    ``|alpha``          ruleset refused, "Invalid 'al' Hex detected"
    ``alpha|4``         loads, matches nothing, 0x04 appended
    ``alpha|41``        matches ``alphaA``; the pair lands on the end
    ``alpha|412``       loads, matches nothing
    ``alpha|4142``      loads, matches nothing
    ==================  ==========================================

    Measured on a locally built Sagan, one reduced rule per row. The two benign
    rows are why this cannot simply flag an odd number of pipes.
    """
    if value.count("|") % 2 == 0:
        return None
    tail = value.rsplit("|", 1)[1]
    if tail == "":
        return None
    if not all(c in _HEX for c in tail[:2]):
        return (
            DefectCode.WILL_NOT_LOAD,
            f"the hex sequence opened in {value!r} is never closed, and "
            f"{tail[:2]!r} is not hex; Validate_HEX aborts the load",
        )
    if len(tail) == 2:
        return None
    return (
        DefectCode.CANNOT_MATCH,
        f"the hex sequence opened in {value!r} is never closed, so the parser "
        f"converts {tail!r} and appends a control byte no message carries",
    )


#: Tracking keys the `threshold` parser recognises, and how it recognises them.
#:
#: It differs from `after` in both the set and the test. `by_string` is a real
#: synonym for `by_username` here, that parser reading the intact option token,
#: while under `after` a `strtok_r` on " " truncates the token to "track" before
#: the comparison, so the branch can never fire.
#:
#: And the test is `Sagan_strstr` against the whole track value rather than a
#: per-token `strcmp`, so a key counts when it appears anywhere in the value.
#: That is why `by_src&byusername` keeps `by_src` and loses the username:
#: "by_username" is not a substring of it, the underscore being absent.
#: Measured on sid 5014022's shape, three events with different usernames from
#: one source under `type suppress, count 1`: `by_src&by_username` alerts three
#: times, `by_src&byusername` once, and `by_src` alone once. The typo behaves
#: exactly like dropping the key.
THRESHOLD_KEYS = AFTER_KEYS | {"by_string"}

_THRESHOLD_TRACK = re.compile(r"track\s+([a-z_&]+)", re.I)


def _threshold_keys(rule: SaganRule) -> list[tuple[str, set[str]]]:
    """Each `threshold` option's track value, and the tokens it names."""
    found: list[tuple[str, set[str]]] = []
    for option in rule.iter_options("threshold"):
        if option.value is None:
            continue
        match = _THRESHOLD_TRACK.search(option.value)
        if match:
            whole = match.group(1).lower()
            found.append((whole, {k.strip() for k in whole.split("&") if k.strip()}))
    return found


def _after_keys(rule: SaganRule) -> list[set[str]]:
    """The tracking keys each `after` option names."""
    keys: list[set[str]] = []
    for option in rule.iter_options("after"):
        if option.value is None:
            continue
        match = _TRACK.search(option.value)
        if match:
            keys.append(
                {k.strip().lower() for k in match.group(1).split("&") if k.strip()}
            )
    return keys


def inspect(rule: SaganRule) -> list[UpstreamDefect]:
    """Every way this rule fails to do what it says, in Sagan."""
    found: list[UpstreamDefect] = []

    # --- the ruleset will not load -------------------------------------------
    for keys in _after_keys(rule):
        if keys and not (keys & AFTER_KEYS) and not (keys & AFTER_INERT_BUT_COUNTED):
            # The parser needs a validity count of four, made of "track", a
            # recognised key, "count" and "seconds". An unrecognised key scores
            # three and Load_Rules() aborts, so Sagan will not start at all.
            found.append(
                UpstreamDefect(
                    rule.sid,
                    rule.source_file,
                    DefectCode.WILL_NOT_LOAD,
                    f"after tracks {'&'.join(sorted(keys))}, which the parser does "
                    f"not recognise; the engine refuses the whole ruleset",
                )
            )

    for option in rule.iter_options("xbits"):
        if option.value and option.value.split(",")[0].strip().lower() == "toggle":
            # The branch that would handle it is commented out in src/rules.c,
            # so xbit_type stays 0 and the load aborts. The engine's own error
            # message lists the action as valid, which is why it looks fine.
            found.append(
                UpstreamDefect(
                    rule.sid,
                    rule.source_file,
                    DefectCode.WILL_NOT_LOAD,
                    "xbits: toggle is parsed by no branch in the engine; the "
                    "ruleset is refused at load",
                )
            )

    for whole, written in _threshold_keys(rule):
        honoured = {key for key in THRESHOLD_KEYS if key in whole}
        mistyped = sorted(token for token in written if token not in THRESHOLD_KEYS)
        if not honoured:
            found.append(
                UpstreamDefect(
                    rule.sid,
                    rule.source_file,
                    DefectCode.WILL_NOT_LOAD,
                    f"threshold tracks {whole!r}, which the parser does not "
                    f"recognise; the engine refuses the whole ruleset",
                )
            )
        elif mistyped:
            found.append(
                UpstreamDefect(
                    rule.sid,
                    rule.source_file,
                    DefectCode.WRONG_GROUPING,
                    f"threshold tracks {', '.join(mistyped)}, which the parser "
                    f"never finds in the option value; the suppression groups "
                    f"on {', '.join(sorted(honoured))} only",
                )
            )

    # --- the rule loads and can never match ----------------------------------
    for option in rule.iter_options("meta_content"):
        if option.value is None or ":" not in option.value:
            continue
        negated = option.value.lstrip().startswith("!")
        if negated:
            # The value is taken with strtok on ":", so `c:\program files\...`
            # searches for `c`. Negated, that is true of almost no message, so
            # the rule cannot alert. Measured on sid 5009802: the event it is
            # written to catch does not fire it.
            found.append(
                UpstreamDefect(
                    rule.sid,
                    rule.source_file,
                    DefectCode.CANNOT_MATCH,
                    "a negated meta_content value is cut at its first colon, so "
                    "the search is the text before it and the negation is "
                    "almost never satisfied",
                )
            )
            break

    for values in _quoted_items(rule):
        if values.negated or len(values.quoted) < values.total:
            continue
        # Every item of the list is quoted, and the list is an OR, so nothing
        # in it can match a value a producer emits. The condition is required,
        # Sagan ANDing its conditions, so the rule is dead.
        found.append(
            UpstreamDefect(
                rule.sid,
                rule.source_file,
                DefectCode.CANNOT_MATCH,
                f"every {values.keyword} value is wrapped in quotes "
                f"({', '.join(values.quoted)}); the list is compared verbatim, "
                f"so the condition searches for the quotes themselves",
            )
        )
        break

    for match in _JSON_KEY.finditer(rule.raw):
        key = match.group(1)
        if len(key) > MAX_JSON_KEY:
            found.append(
                UpstreamDefect(
                    rule.sid,
                    rule.source_file,
                    DefectCode.CANNOT_MATCH,
                    f"the JSON key path {key!r} is {len(key)} characters; the "
                    f"parser stores only the first {MAX_JSON_KEY}, so this "
                    f"condition can never match",
                )
            )
            break

    # An unterminated hex sequence lands in either category above depending on
    # what follows the pipe, so it is judged once and filed by its own verdict.
    for keyword, value in _piped_values(rule):
        verdict = _unterminated_hex(value)
        if verdict is None:
            continue
        code, detail = verdict
        found.append(
            UpstreamDefect(rule.sid, rule.source_file, code, f"{keyword}: {detail}")
        )
        break

    for option in rule.options:
        if option.name not in _SINGLE_QUOTED or not option.value:
            continue
        argument = _QUOTED_ARGUMENT.match(option.value)
        if argument is None:
            continue
        quoted, remainder = argument.group(1), argument.group(2)
        if quoted == "":
            # `content:""established successfully` is harmless, which is not
            # what it looks like. Between_Quotes lowers its flag on the second
            # quote and raises it again on the same character, so the value
            # captured is the text that follows and the rule matches normally.
            # Measured on a reduced rule: it alerts. Three corpus rules of this
            # shape were first reported as unloadable, which turned out to be
            # Bluedot and dynamic_load in the same files rather than the quotes.
            continue
        if remainder.replace('"', "").strip():
            # A forgotten `;`, so the next option is swallowed into this one.
            # A remainder of nothing but quotes is harmless, measured on sid
            # 5007405, which alerts normally; anything else is not.
            found.append(
                UpstreamDefect(
                    rule.sid,
                    rule.source_file,
                    DefectCode.CANNOT_MATCH,
                    f"the {option.name} option is missing its semicolon, so the "
                    f"text after the closing quote is swallowed into its "
                    f"argument and the rule matches nothing: "
                    f"{option.value.strip()[:60]!r}",
                )
            )
            break

    for option in rule.iter_options("program"):
        if option.value and " " in option.value.strip():
            # Measured: `program: slapd ldap daemon` never matches, whatever the
            # event's program is, while the same name without spaces does.
            found.append(
                UpstreamDefect(
                    rule.sid,
                    rule.source_file,
                    DefectCode.CANNOT_MATCH,
                    f"the program {option.value.strip()!r} contains a space; "
                    f"no event can satisfy it",
                )
            )
            break

    header = rule.header
    if header.protocol.lower() not in SYSLOG_PROTOCOLS and not rule.has(
        "default_proto"
    ):
        found.append(
            UpstreamDefect(
                rule.sid,
                rule.source_file,
                DefectCode.CANNOT_MATCH,
                f"the header asks for protocol {header.protocol!r} and nothing "
                f"sets it; a syslog event defaults to udp, so the rule never "
                f"matches",
            )
        )
    if _enforced_port(header.destination_port) and not rule.has("default_dst_port"):
        found.append(
            UpstreamDefect(
                rule.sid,
                rule.source_file,
                DefectCode.CANNOT_MATCH,
                f"the header asks for destination port "
                f"{header.destination_port!r} and no default_dst_port supplies "
                f"one, so the rule never matches",
            )
        )

    searched = set(_JSON_KEY.findall(rule.raw)) | set(_JSON_PCRE_KEY.findall(rule.raw))
    for short, full in rule.key_restorations.items():
        # Only when the key is a detection condition. The same unreachable path
        # under `json_map` binds an internal value and nothing else, so the
        # rule still fires on its other conditions and is not dead; flagging
        # those too reported 17 rules where 5 are dead.
        if short in searched and "." in full[MAX_JSON_KEY:]:
            # Upstream's workaround for the engine's key limit is to name the
            # clipped path, which the engine matches against its own clipped
            # copy. That only holds when the clip lands on the last segment:
            # `data.authorizationInfo.operation` clips to a leaf and matches,
            # while `data.authenticationInfo.metadata.mechanism` clips inside
            # `metadata`, leaving `mechanism` below the stored path where
            # nothing reaches it. Measured both ways on the deep path: neither
            # the clipped nor the full key matches, and depth alone is not the
            # cause, five short levels matching fine.
            found.append(
                UpstreamDefect(
                    rule.sid,
                    rule.source_file,
                    DefectCode.CANNOT_MATCH,
                    f"the key path {full!r} is clipped to {short!r} by the "
                    f"engine, and the rest of the path lies below that point, "
                    f"so no spelling of the key can reach the value",
                )
            )
            break

    # --- the rule loads, matches, and means the opposite ---------------------
    for option in rule.iter_options("pcre"):
        if option.value and option.value.lstrip().startswith("!"):
            # `content` has Check_Content_Not; `pcre` has no equivalent. The
            # parser hands the quoted pattern straight to Between_Quotes and
            # PcreS() counts matches with no negation flag anywhere, so the `!`
            # is dropped and the condition asserts what it meant to forbid.
            # Measured both ways: absent pattern stays silent, present pattern
            # alerts, which is exactly backwards.
            found.append(
                UpstreamDefect(
                    rule.sid,
                    rule.source_file,
                    DefectCode.INVERTED_CONDITION,
                    "a negated pcre is read as a positive one: Sagan has no "
                    "negation for pcre, so the rule requires what it means to "
                    "exclude",
                )
            )
            break

    # --- the rule loads, matches, and one condition never bites --------------
    for values in _quoted_items(rule):
        if not values.negated or len(values.quoted) < values.total:
            continue
        # The mirror image of the case above. An exclusion that can match
        # nothing excludes nothing, so the rule alerts on the very events it
        # names as exceptions, and does so silently: it fires more, not less.
        # sid 5014486 excludes `"analytics"` with its quotes and therefore
        # never excludes an eventtype of analytics.
        found.append(
            UpstreamDefect(
                rule.sid,
                rule.source_file,
                DefectCode.INERT_CONDITION,
                f"the negated {values.keyword} values are wrapped in quotes "
                f"({', '.join(values.quoted)}); the list is compared verbatim, "
                f"so the exclusion matches nothing and never excludes anything",
            )
        )
        break

    # --- the rule loads, matches, and groups on the wrong thing --------------
    for keys in _after_keys(rule):
        mistyped = sorted(
            k for k in keys if k not in AFTER_KEYS | AFTER_INERT_BUT_COUNTED
        )
        if mistyped and (keys & AFTER_KEYS):
            found.append(
                UpstreamDefect(
                    rule.sid,
                    rule.source_file,
                    DefectCode.WRONG_GROUPING,
                    f"after tracks {', '.join(mistyped)}, which the parser "
                    f"ignores; the correlation groups on the remaining keys only",
                )
            )

    return found
