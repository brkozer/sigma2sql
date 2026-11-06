# Supported features

What sigma2sql supports on each database, how values are compared, and what happens to a rule
it cannot translate. For how this is verified, see [how it is checked](correctness.md).

## Support matrix

| Feature | SQLite | PostgreSQL | DuckDB | ClickHouse |
| --- | --- | --- | --- | --- |
| maps, lists, keywords (with `all`, `re` and string modifiers) | ✓ | ✓ | ✓ | ✓ |
| `and`, `or`, `not`, `1 of x*`, `all of x*`, `them`, condition lists | ✓ | ✓ | ✓ | ✓ |
| wildcards and escapes, `contains`, `startswith`, `endswith`, `all`, `cased`, `windash`, `neq` | ✓ | ✓ | ✓ | ✓ |
| `base64`, `base64offset`, `utf16`, `utf16le`, `utf16be`, `wide` | ✓ | ✓ | ✓ | ✓ |
| `re` with `i`, `m`, `s` | `REGEXP` ¹ | `~` ² | `regexp_matches` ³ | `match` ³ |
| `cidr` (IPv4 and IPv6, any notation) | `cidr_match()` ¹ | `inet <<=` | `cidr_match()` ¹ | `isIPAddressInRange` |
| `lt`, `lte`, `gt`, `gte`, `exists`, `fieldref`, `null` | ✓ | ✓ | ✓ | ✓ ⁴ |
| `minute`, `hour`, `day`, `week`, `month`, `year` (UTC, ISO weeks) | ✓ | ✓ | ✓ | ✓ |
| `expand` placeholders, filters | ✓ | ✓ | ✓ | ✓ |
| correlations, `temporal_ordered` included, `count()` aggregations | ✓ ¹ | ✓ | ✓ | ✓ ⁵ |
| `temporal` with a boolean condition | – | – | – | – |

¹ Not built into the database. `hunt`, `test` and `check` register what they need. When you
run the SQL elsewhere, register `regexp(pattern, value)`, `cidr_match(value, network)` and, for
percentiles, the aggregate `sigma_percentile(value, fraction)` yourself.
`sigma2sql.runner.connect()` returns a SQLite connection with all three
([library use](library.md)). On DuckDB only `cidr_match` is needed.

² PostgreSQL rejects repetition counts above 255; those rules are reported as unsupported
rather than silently changed. Without `s` or `m`, `.` still matches a newline there. Values
such as `-` in an address or number field are skipped with `pg_input_is_valid`, so `cidr`,
comparisons and correlations need PostgreSQL 16 or newer.

³ RE2: no lookaround or backreferences; such rules are reported as unsupported. Repetition
counts above 1000 are reported too.

⁴ Without `--json-column`, a missing value is only NULL in `Nullable` columns.

⁵ Tested on ClickHouse 25.8. Correlations with `group-by` need `IS NOT DISTINCT FROM` in
`JOIN ON`. One SigmaHQ rule, a list of driver hashes, is larger than the default
`max_query_size` of 256 KiB and needs that setting raised.

The correlation types and how their windows work are on the
[correlations page](correlations.md).

## Conditions

Precedence from low to high is `or`, `and`, `not`. These words can be in any case, and
parentheses work as usual.

- `1 of x*` and `all of x*` take the searches whose names match the pattern. Other counts are
  not supported: `2 of x*` gives `condition refers to unknown search '2'`.
- `1 of them` and `all of them` take all searches except the ones whose names start with `_`.
- A list of conditions means any of them.
- A search that the condition does not use is not compiled, so a problem inside it has no
  effect.

## Values and modifiers

Without a modifier, a value must equal the whole field. A list means any of its values, and a
map means all of its fields.

In a string, `*` matches any text and `?` one character. `\*`, `\?` and `\\` are escapes; any
other backslash is literal, so `C:\Windows\` needs no doubling.

| Modifier | Behaviour |
| --- | --- |
| `contains`, `startswith`, `endswith` | At most one of them per field |
| `all` | All values of the list must match instead of any |
| `cased` | Case-sensitive, see [below](#case-sensitivity) |
| `windash` | A `-` or `/` that starts a word also matches the other one, an en dash, an em dash and a horizontal bar. Up to three such flags in a value are combined in every way; with more, all of them use the same character |
| `neq` | Negates the field's test, so `a|neq: [x, y]` is neither `x` nor `y`. True on a missing field |
| `base64`, `base64offset` | Match the encoded value. Always case-sensitive, and the value cannot have wildcards |
| `utf16`, `utf16le`, `utf16be`, `wide` | Encode the text first. Only together with `base64` or `base64offset`. `utf16` adds the little-endian byte order mark |
| `re` | Regular expression, found anywhere in the value, case-sensitive |
| `i`, `m`, `s` | Regular expression flags, also as `ignorecase`, `multiline`, `dotall`. They need `re`. Flags written at the start of the pattern, such as `(?i)`, are merged with these |
| `cidr` | Value is an address inside the network. The address is parsed, so `0:0:0:0:0:0:0:1` is in `::1/128`. Anything that is not an address does not match |
| `lt`, `lte`, `gt`, `gte` | Numeric comparison. The rule's value must be a number |
| `exists` | Takes `true` or `false` |
| `fieldref` | The value names another field, and the two must be equal. This is always a plain, case-sensitive equality: `contains`, `startswith`, `endswith` and `cased` have no effect with it |
| `minute`, `hour`, `day`, `week`, `month`, `year` | One part of a time field, in UTC, read with the [timestamp format](profiles.md#event-time). Weeks are ISO 8601 weeks |
| `expand` | Fills in `%name%` [placeholders](placeholders.md) |

An unknown modifier is an error, not ignored.

## Keywords

A plain value, a list of them, or a map with an empty field name such as `'|all': [a, b]`,
searches the whole event. A keyword behaves like `contains`, whichever position modifier it has,
and is case-insensitive unless it has `cased`. A list of keywords means any of them; with `all`,
all of them.

The modifiers `cidr`, `exists`, `fieldref`, `neq`, the comparisons and the time parts make no
sense without a field and are not supported on keywords.

Keywords need something to search. With `--keyword-column` that is the column you name. In JSON
mode it is the whole document, and `hunt`, `test` and `check` are always in JSON mode. Otherwise
the rule is reported as unsupported.

In JSON mode a keyword searches the document's JSON text, not its values, which has three
effects:

- Key names match too. The keyword `Image` matches any event with an `Image` field.
- Backslashes and double quotes are escaped in JSON. On the event
  `{"Image": "C:\\Windows\\cmd.exe"}` the keyword `C:\Windows\cmd.exe` finds nothing, and
  `C:\\\\Windows\\\\cmd.exe`, which is the text as stored, matches.
- `hunt` keeps the text of a JSON file as it is, so a character written there as `\uXXXX` stays
  an escape, and the keyword `şifre` does not match it. `test`, `check` and `hunt` on `.evtx`
  files store the characters themselves, so it matches there. A search on a field is not
  affected.

## Case sensitivity

Sigma values are case-insensitive by default. Regular expressions, `base64`, `base64offset` and
`fieldref` are case-sensitive, and `cased` makes a string case-sensitive.

[How it works](how-it-works.md#text) shows the SQL on each database.

SQLite's `NOCASE` and `LIKE` only fold ASCII. `User|startswith: ÇAĞ` does not match `çağrı`
there, and it does on DuckDB. This applies to `test` and `check` as well, because they run
on SQLite.

## Numbers, booleans and strings

A rule's number is compared as text in a JSON column, so `EventID: 4624` matches `4624` and
`"4624"` on every database. Without a JSON column it is `column = 4624`.

A string in a rule is different. On PostgreSQL, DuckDB and ClickHouse JSON values are read as
text, so the string matches a stored number too. SQLite keeps the JSON type, and a plain string
only matches a string. `true` and `false` in a rule are strings as well, with the same result
on SQLite:

| Rule | Event | SQLite (`test`, `check`) | DuckDB (`hunt`) |
| --- | --- | --- | --- |
| `EventID: 4624` | `{"EventID": 4624}` | match | match |
| `EventID: 4624` | `{"EventID": "4624"}` | match | match |
| `EventID: '4624'` | `{"EventID": 4624}` | no match | match |
| `EventID: '4624'` | `{"EventID": "4624"}` | match | match |
| `Enabled: true` | `{"Enabled": true}` | no match | match |
| `Enabled: true` | `{"Enabled": "true"}` | match | match |
| `EventID|contains: '62'` | `{"EventID": 4624}` | match | match |

As the last row shows, wildcards, position modifiers and `re` read a stored number as text on
SQLite as well. A stored boolean is 1 there, so `Enabled|contains: tru` does not match `true`.

So write numbers in rules as numbers. A `where` in a profile follows the same rules.

In `lt`, `lte`, `gt` and `gte`, a JSON value that cannot be read as a number does not match, and
it does not end the query. What counts as a number differs a little. PostgreSQL and DuckDB try
a cast and treat a failure as NULL. ClickHouse first matches the whole text against the form of
a number, as its cast reads `"e5"` as 0 and `"1e+"` as 1, and takes `nan` and `inf`. SQLite has
no such cast, so it looks at the text: digits, at most one `.`, at most one exponent with digits
before and after it, and a sign only at the start or right after the `e`. It allows no spaces,
and a JSON `true` is 1 there. This is `Port|lt: 100`, and `not` of the same search gives the
opposite in every row:

| Event | SQLite (`test`, `check`) | DuckDB (`hunt`) |
| --- | --- | --- |
| `{"Port": 80}` | match | match |
| `{"Port": "80"}` | match | match |
| `{"Port": "n/a"}` | no match | no match |
| `{"Port": "-"}` | no match | no match |
| `{}` | no match | no match |
| `{"Port": "10.0.0.1"}` | no match | no match |
| `{"Port": "e5"}` | no match | no match |
| `{"Port": ".e5"}` | no match | no match |
| `{"Port": "1e+"}` | no match | no match |
| `{"Port": true}` | match | no match |
| `{"Port": " 80"}` | no match | match |

Without a JSON column the column is compared as it is, with the database's own rules for its
type.

## Null and missing fields

A missing field is NULL in SQL, and a JSON `null` is read the same way, so the two cannot be
told apart. Sigma treats a test on a missing field as no match, and so `not` of that test is
true. SQL's NULL would make it unknown instead, which is why every `not` and `neq` is written
with `COALESCE`:

```console
$ sigma2sql convert not_user_admin.yml --json-column data
-- not_user_admin
SELECT * FROM "events" WHERE NOT COALESCE(json_extract("data", '$."User"') = 'admin' COLLATE NOCASE, FALSE);
```

These results are from `test` (SQLite) and `hunt` (DuckDB), which agree on all of them:

| Search | `"admin"` | `""` | `null` | missing |
| --- | --- | --- | --- | --- |
| `User: admin` | match | no | no | no |
| `not` of the same search | no | match | match | match |
| `User|neq: admin` | no | match | match | match |
| `User: null` | no | no | match | match |
| `User|exists: true` | match | match | no | no |
| `User|exists: false` | no | no | match | match |
| `User: ''` | no | match | no | no |
| `User|contains: ''` | match | match | no | no |

An empty string is a value, not a missing field. In a list, `null` is one of the alternatives:
`User: [admin, null]` means `admin` or missing. A keyword cannot be `null`.

## What is not supported

| Rule uses | Reported as |
| --- | --- |
| `temporal` with a boolean condition | `correlation 'condition' must be a map` |
| `temporal_ordered` with a `condition` other than `gte` the number of steps | `temporal_ordered needs all of its rules, in order` |
| another correlation type | `correlation type 'x' is not supported` |
| an aggregation other than `count()`, such as `sum` or `near` | `aggregation 'sum(bytes) > 5' is not supported (only count)` |
| an aggregation in a list of conditions | `aggregations need a single condition` |
| an aggregation in a filter | `aggregations are not supported in filters` |
| `action: global` collections | `legacy rule collections ('action: global') are not supported` |
| an unknown modifier | `modifier 'sha256' is not supported` |
| a modifier that needs a field, on keywords | `modifier 'cidr' is not supported on keywords` |
| `utf16`, `wide` and the like without base64 | `wide is only supported together with base64` |
| wildcards with base64 | `base64 modifiers cannot encode wildcards` |
| keywords with no column to search | `keyword searches need a keyword column or a JSON column` |
| a regular expression Python cannot compile, in `test` and `check` | `invalid regex '(': ...` |
| lookaround or backreferences on RE2 | `duckdb (RE2) has no lookaround or backreferences: ...` |
| a repetition count over the limit | `postgres regexes allow at most 255 repetitions: ...` |
| a placeholder with no value | `placeholder %dc% has no value (see --placeholders)` |

The last four depend on the database or options, so the same rule can work on one target and
not on another. Rules that are not valid Sigma, such as one with a missing `detection` section
or a condition that names an unknown search, are reported the same way.

A problem found while reading a file applies to the whole file. A `temporal` correlation with a
boolean condition takes the rules in that file with it. The same goes for a rule with an
unsupported aggregation and any other document in the file. A problem found while building a
rule's SQL, such as an unknown modifier, only affects that rule.

## How it is reported

Each command reports a rule it cannot use, with the reason, and goes on with the rest where it
can. `convert`, `hunt` and `test` write this to stderr, `check` to stdout.

`convert` leaves the rule out, names it and exits with 1. `sigma2sql: no .yml or .yaml files
found` with exit code 2 means there was nothing to convert. The same directory gives a
different result per dialect, here for a lookahead:

```console
$ sigma2sql convert rules
skip rules/boolean.yml: correlation 'condition' must be a map
skip rules/sum.yml: aggregation 'sum(bytes) > 5' is not supported (only count)
-- A plain rule
SELECT * FROM "events" WHERE "Image" = 'x' COLLATE NOCASE;

skip rules/hash.yml: modifier 'sha256' is not supported
-- Lookahead
SELECT * FROM "events" WHERE "Image" REGEXP 'cmd(?!\.exe)';

converted 2/5 rules

$ sigma2sql convert rules -d duckdb
skip rules/boolean.yml: correlation 'condition' must be a map
skip rules/sum.yml: aggregation 'sum(bytes) > 5' is not supported (only count)
-- A plain rule
SELECT * FROM "events" WHERE LOWER("Image") = 'x';

skip rules/hash.yml: modifier 'sha256' is not supported
skip rules/lookahead.yml: duckdb (RE2) has no lookaround or backreferences: cmd(?!\.exe)
converted 1/5 rules
```

`hunt` names the skipped rules and counts them in its summary. Skipped rules do not change the
exit code as long as one rule ran, so a CI job that must notice them has to read stderr. If
none could run, the exit code is 2. A query that DuckDB itself rejects is skipped the same way
and does not end the hunt.

```console
$ sigma2sql hunt rules --logs events.jsonl
skip rules/boolean.yml: correlation 'condition' must be a map
skip rules/sum.yml: aggregation 'sum(bytes) > 5' is not supported (only count)
skip rules/hash.yml: modifier 'sha256' is not supported
skip rules/lookahead.yml: duckdb (RE2) has no lookaround or backreferences: cmd(?!\.exe)
LEVEL         HITS  RULE
-                1  A plain rule  (rules/good.yml)
1 of 1 rules matched 1 events (4 rules skipped)
```

`test` stops with exit code 2:

```console
$ sigma2sql test rules/hash.yml events.jsonl
sigma2sql: Unknown modifier: modifier 'sha256' is not supported

$ sigma2sql test rules/boolean.yml events.jsonl
skip rules/boolean.yml: correlation 'condition' must be a map
```

`check` turns the problem into a failed test with exit code 1, with or without test files. See
[Failures](testing.md#failures).

| Command | Rule it cannot use | Exit code |
| --- | --- | --- |
| `convert` | `skip PATH: reason`, the rest is converted | 1 |
| `hunt` | `skip PATH: reason`, counted in the summary | unchanged, or 2 if no rule could run |
| `test` | message, stops | 2 |
| `check` | `FAIL PATH: reason` | 1 |

There are two gaps. A regular expression that does not compile is not always found early.
`test` and `check` compile every pattern first, so they report it even if no event reaches it,
but `convert` prints it as written and `hunt` skips the rule only when DuckDB rejects it. And
some modifiers are ignored instead of reported: position modifiers on keywords, and `contains`,
`startswith`, `endswith` and `cased` with `fieldref`.
