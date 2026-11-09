# Convert rules

`sigma2sql convert` prints SQL for rules and correlations. Use it when your events already live
in a database. To search log files without one, use [`hunt`](hunt.md).

```console
$ sigma2sql convert examples/rules/rdp_from_outside.yml
-- Successful RDP logon from a public address (c2d4e6f8-0a1b-4c3d-8e5f-6a7b8c9d0e03)
SELECT * FROM "events" WHERE (("EventID" = 4624 AND "LogonType" = 10) AND NOT COALESCE((cidr_match("IpAddress", '10.0.0.0/8') OR cidr_match("IpAddress", '172.16.0.0/12') OR cidr_match("IpAddress", '192.168.0.0/16') OR cidr_match("IpAddress", '127.0.0.0/8')), FALSE));
```

Each rule becomes a comment line with its title, and its id if it has one, then one statement
ending in `;` and a blank line. sigma2sql does not connect to any database here.

## Options

```text
sigma2sql convert [options] PATH [PATH ...]
```

`PATH` is a rule file or a directory. Files and directories can be mixed.

| Option | Default | Meaning |
| --- | --- | --- |
| `-d`, `--dialect` | `sqlite` | `sqlite`, `postgres`, `duckdb` or `clickhouse` |
| `-t`, `--table` | `events` | table name; `schema.table` is split at the dots and each part quoted |
| `--json-column COL` | none | every event is one JSON object in this column |
| `--keyword-column COL` | none | column searched by keyword rules |
| `-p`, `--profile NAME` | none | built-in [profile](profiles.md) or a path to a YAML file |
| `-m`, `--mapping FILE` | none | YAML map of Sigma field to column or key, applied over the profile |
| `--placeholders FILE` | none | values for [`%name%` placeholders](placeholders.md) |
| `--nested` | off | dotted names are paths into nested JSON; needs `--json-column` to have any effect |
| `--timestamp-field NAME` | `timestamp` | event time field for [correlations](correlations.md) |
| `--timestamp-format FMT` | `iso` | `iso`, `epoch_s` or `epoch_ms` |

Settings are applied in this order: defaults, then the profile, then the options above, so
`--json-column` wins over a profile that sets `json_column`. None of the built-in profiles sets
it. One case differs: a table named by a profile's `logsources` entry wins over `-t` for the
rules it matches.

## Columns or a JSON column

Without `--json-column`, each Sigma field is a column of the same name, and a number in the
rule is compared as a number:

```yaml
title: Remote logon
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
    LogonType: 10
    TargetUserName: admin
  condition: selection
level: medium
```

```console
$ sigma2sql convert logon.yml
-- Remote logon
SELECT * FROM "events" WHERE ("EventID" = 4624 AND "LogonType" = 10 AND "TargetUserName" = 'admin' COLLATE NOCASE);
```

With `--json-column`, every field is a key of the JSON object in that column:

```console
$ sigma2sql convert logon.yml --json-column data
-- Remote logon
SELECT * FROM "events" WHERE (CAST(json_extract("data", '$."EventID"') AS TEXT) = '4624' AND CAST(json_extract("data", '$."LogonType"') AS TEXT) = '10' AND json_extract("data", '$."TargetUserName"') = 'admin' COLLATE NOCASE);
```

The number is now compared as text, so an event matches whether it stores `4624` or `"4624"`.
Without a JSON column the value is compared as a number, with no conversion.

Keys are top-level unless you pass `--nested`. A dotted name then becomes a path:

```yaml
TargetUserName: user.name
EventID: event.code
```

```console
$ sigma2sql convert logon.yml --json-column raw -m map2.yml
-- Remote logon
SELECT * FROM "events" WHERE (CAST(json_extract("raw", '$."event.code"') AS TEXT) = '4624' AND CAST(json_extract("raw", '$."LogonType"') AS TEXT) = '10' AND json_extract("raw", '$."user.name"') = 'admin' COLLATE NOCASE);

$ sigma2sql convert logon.yml --json-column raw -m map2.yml --nested
-- Remote logon
SELECT * FROM "events" WHERE (CAST(json_extract("raw", '$."event"."code"') AS TEXT) = '4624' AND CAST(json_extract("raw", '$."LogonType"') AS TEXT) = '10' AND json_extract("raw", '$."user"."name"') = 'admin' COLLATE NOCASE);
```

The first command looks for a key that has a dot in its name. The second walks into `event` and
`user`.

### Renaming fields and tables

`-m` renames fields. Fields it does not list keep their Sigma name. It only holds one name per
field; for several candidates, or for a whole schema, write a [profile](profiles.md).

```yaml
TargetUserName: user_name
EventID: event_id
```

```console
$ sigma2sql convert logon.yml -t security.logons -m map.yml
-- Remote logon
SELECT * FROM "security"."logons" WHERE ("event_id" = 4624 AND "LogonType" = 10 AND "user_name" = 'admin' COLLATE NOCASE);
```

With a profile, the same rule also picks up the condition of its log source:

```console
$ sigma2sql convert logon.yml -d postgres --json-column data -p evtx
-- Remote logon
SELECT * FROM "events" WHERE (LOWER("data"#>>'{"Event","System","Channel"}') = 'security' AND (COALESCE("data"#>>'{"Event","System","EventID","#text"}', "data"#>>'{"Event","System","EventID"}') = '4624' AND COALESCE("data"#>>'{"Event","EventData","LogonType"}', "data"#>>'{"Event","EventData","Logon Type"}') = '10' AND LOWER(COALESCE("data"#>>'{"Event","EventData","TargetUserName"}', "data"#>>'{"Event","EventData","Target User Name"}')) = 'admin'));
```

### Keyword rules

A keyword rule has no field, so it needs something to search:

```yaml
title: Mimikatz keyword
detection:
  keywords:
    - sekurlsa
  condition: keywords
level: high
```

```console
$ sigma2sql convert mimikatz.yml --keyword-column message
-- Mimikatz keyword
SELECT * FROM "events" WHERE "message" LIKE '%sekurlsa%' ESCAPE '\';

$ sigma2sql convert mimikatz.yml --json-column data
-- Mimikatz keyword
SELECT * FROM "events" WHERE "data" LIKE '%sekurlsa%' ESCAPE '\';
```

`--keyword-column` wins when both options are given. With `--json-column` alone the whole JSON
document is searched as text. With neither, the rule is skipped:

```console
$ sigma2sql convert mimikatz.yml
skip mimikatz.yml: keyword searches need a keyword column or a JSON column
```

## Output per dialect

The same rule on each database, with a JSON column:

```yaml
title: Tool checks
detection:
  address:
    SourceIp|cidr: 10.0.0.0/8
  path:
    Image|re: '\\temp\\[a-z]+\.exe$'
  port:
    DestinationPort|lt: 1024
  condition: address and path and port
```

=== "SQLite"

    ```console
    $ sigma2sql convert tools.yml --json-column data
    -- Tool checks
    SELECT * FROM "events" WHERE (cidr_match(json_extract("data", '$."SourceIp"'), '10.0.0.0/8') AND json_extract("data", '$."Image"') REGEXP '\\temp\\[a-z]+\.exe$' AND CASE WHEN CAST(json_extract("data", '$."DestinationPort"') AS TEXT) GLOB '*[0-9]*' AND CAST(json_extract("data", '$."DestinationPort"') AS TEXT) NOT GLOB '*[^0-9.eE+-]*' AND CAST(json_extract("data", '$."DestinationPort"') AS TEXT) NOT GLOB '*.*.*' AND CAST(json_extract("data", '$."DestinationPort"') AS TEXT) NOT GLOB '*[eE]*[eE.]*' AND CAST(json_extract("data", '$."DestinationPort"') AS TEXT) NOT GLOB '*[0-9.][+-]*' AND CAST(json_extract("data", '$."DestinationPort"') AS TEXT) NOT GLOB '*[+-][+eE-]*' AND CAST(json_extract("data", '$."DestinationPort"') AS TEXT) NOT GLOB '[eE]*' AND CAST(json_extract("data", '$."DestinationPort"') AS TEXT) NOT GLOB '.[eE]*' AND CAST(json_extract("data", '$."DestinationPort"') AS TEXT) NOT GLOB '[+-].[eE]*' AND CAST(json_extract("data", '$."DestinationPort"') AS TEXT) NOT GLOB '*[eE+-]' THEN CAST(json_extract("data", '$."DestinationPort"') AS REAL) END < 1024);
    ```

=== "PostgreSQL"

    ```console
    $ sigma2sql convert tools.yml --json-column data -d postgres
    -- Tool checks
    SELECT * FROM "events" WHERE (CASE WHEN pg_input_is_valid(("data"->>'SourceIp')::text, 'inet') THEN ("data"->>'SourceIp')::inet END <<= '10.0.0.0/8'::inet AND "data"->>'Image' ~ '\\temp\\[a-z]+\.exe$' AND CASE WHEN pg_input_is_valid(("data"->>'DestinationPort')::text, 'numeric') THEN ("data"->>'DestinationPort')::numeric END < 1024);
    ```

=== "DuckDB"

    ```console
    $ sigma2sql convert tools.yml --json-column data -d duckdb
    -- Tool checks
    SELECT * FROM "events" WHERE (cidr_match(("data"->>'$."SourceIp"'), '10.0.0.0/8') AND regexp_matches(("data"->>'$."Image"'), '\\temp\\[a-z]+\.exe$') AND TRY_CAST(("data"->>'$."DestinationPort"') AS DOUBLE) < 1024);
    ```

=== "ClickHouse"

    ```console
    $ sigma2sql convert tools.yml --json-column data -d clickhouse
    -- Tool checks
    SELECT * FROM "events" WHERE (((isIPv4String(toString(JSONExtract("data", 'SourceIp', 'Nullable(String)'))) OR isIPv6String(toString(JSONExtract("data", 'SourceIp', 'Nullable(String)')))) AND isIPAddressInRange(toString(JSONExtract("data", 'SourceIp', 'Nullable(String)')), '10.0.0.0/8')) AND match(JSONExtract("data", 'Image', 'Nullable(String)'), '(?-s)\\\\temp\\\\[a-z]+\\.exe$') AND if(match(JSONExtract("data", 'DestinationPort', 'Nullable(String)'), '^[+-]?([0-9]+[.]?[0-9]*|[.][0-9]+)([eE][+-]?[0-9]+)?$'), toFloat64OrNull(JSONExtract("data", 'DestinationPort', 'Nullable(String)')), NULL) < 1024);
    ```

How each test is written:

| Test | SQLite | PostgreSQL | DuckDB | ClickHouse |
| --- | --- | --- | --- | --- |
| equal, any case | `= 'x' COLLATE NOCASE` | `LOWER(col) = 'x'` | `LOWER(col) = 'x'` | `lowerUTF8(col) = 'x'` |
| wildcard, any case | `LIKE` | `ILIKE` | `ILIKE` | `ILIKE` |
| wildcard, `cased` | `GLOB` | `LIKE` | `LIKE` | `LIKE` |
| `re` | `REGEXP` | `~` | `regexp_matches()` | `match()` |
| `cidr` | `cidr_match()` | `<<=` on `inet` | `cidr_match()` | `isIPAddressInRange()` |
| `lt`, `lte`, `gt`, `gte` in JSON | `CASE` with `GLOB` | `pg_input_is_valid` | `TRY_CAST` | `match()` and `toFloat64OrNull` |
| JSON key | `json_extract` | `->>`, `#>>` | `->>` | `JSONExtract` |

Things to know before you run the SQL:

- **SQLite** has no `REGEXP`, `cidr_match` or percentile function built in. Register
  `regexp(pattern, value)`, `cidr_match(value, network)` and the aggregate
  `sigma_percentile(value, fraction)`, or use `sigma2sql.runner.connect()`, which returns a
  connection that has all three. See [library use](library.md). `LIKE` and `NOCASE` only fold
  ASCII there.
- **DuckDB** has no `cidr_match` built in either. `hunt` registers it; elsewhere you do.
- **PostgreSQL** needs version 16 or newer for `cidr`, number comparisons in a JSON column, the
  time modifiers such as `hour`, and correlations, because bad values such as a `-` in an
  address field are skipped with `pg_input_is_valid`. A cast that fails would end the whole
  query.
- **ClickHouse** treats a backslash in a string literal as an escape, so every backslash is
  doubled and `LIKE` has no `ESCAPE` clause. `match()` lets `.` reach newlines by default and
  Sigma regexes do not, so patterns start with `(?-s)` unless the rule sets `s`.

Rules with very long lists stay runnable. An `AND` or `OR` of more than 50 terms is split into
nested groups of up to 50, because SQLite stops at a parser depth of 1000. On DuckDB, more than
50 case-insensitive string tests on one field become a single `list_filter` test, because it
runs out of memory on thousands of `OR` terms.

The full table of features per database is on [supported features](features.md).

## Directories

A directory is searched recursively for files ending in `.yml` or `.yaml`, in sorted order. The
suffix can be in upper or lower case, so `RULE.YML` is picked up too. A file you name directly
is read whatever it is called.

Each path can hold many rules, and a file can hold several YAML documents. SQL goes to stdout
and everything else goes to stderr, so a redirect gives a clean file:

```console
$ sigma2sql convert examples/rules -d postgres --json-column event > rules.sql
converted 4/4 rules
$ grep '^--' rules.sql
-- PowerShell started with an encoded command (5f0c2b2e-1d55-4c1a-9a51-7d1b0e3c6a01)
-- Office application starting a shell (8a7f3e91-2c44-4b8e-b0f6-3e5d9c1a7b02)
-- Successful RDP logon from a public address (c2d4e6f8-0a1b-4c3d-8e5f-6a7b8c9d0e03)
-- Brute force against one account (9e8d7c6b-5a49-4382-a1b0-c9d8e7f6a505)
```

Detection rules come first, then correlations. `examples/rules/brute_force.yml` holds two
documents, a rule and a correlation, but only the correlation is listed. A rule used by a
correlation does not get a query of its own unless the correlation sets [`generate:
true`](correlations.md#generate).

`converted N/M rules` appears when there is more than one item. `M` counts every rule and
correlation that should produce a query, plus every file that could not be loaded.

Other YAML files in the tree are treated as rules and reported as skipped, so keep profiles and
placeholder values outside the directory you convert.

## Unsupported rules

A rule that cannot be converted is skipped with the reason on stderr. The others still convert:

```console
$ sigma2sql convert rules -d duckdb > rules.sql; echo $?
skip rules/boolean.yml: correlation 'condition' must be a map
skip rules/broken.yml: missing 'detection' section
skip rules/lookahead.yml: duckdb (RE2) has no lookaround or backreferences: foo(?!bar)
skip rules/mimikatz.yml: keyword searches need a keyword column or a JSON column
skip rules/modifier.yml: modifier 'sounds_like' is not supported
converted 1/6 rules
1
```

Whether a rule converts can depend on the dialect. `lookahead.yml` is fine on SQLite and
PostgreSQL, and is skipped here because DuckDB uses RE2.

The common reasons:

| Message | Cause |
| --- | --- |
| `modifier 'x' is not supported` | a modifier sigma2sql does not know |
| `modifier 'x' is not supported on keywords` | a field modifier on a keyword search, such as `'|cidr'` |
| `CommandLine: regex flags need the re modifier` | `i`, `m` or `s` without `re` |
| `wide is only supported together with base64` | an encoding modifier alone |
| `base64 modifiers cannot encode wildcards` | `*` or `?` in a `base64` value |
| `keyword searches need a keyword column or a JSON column` | see [keyword rules](#keyword-rules) |
| `postgres regexes allow at most 255 repetitions: ...` | a `{m,n}` count above 255; the limit is 1000 on DuckDB and ClickHouse, and SQLite has none |
| `duckdb (RE2) has no lookaround or backreferences: ...` | a lookahead, lookbehind or backreference; ClickHouse has the same limit |
| `placeholder %x% has no value (see --placeholders)` | see [placeholders](placeholders.md) |
| `correlation 'condition' must be a map` | a boolean condition, see [correlations](correlations.md#not-supported) |
| `temporal_ordered needs all of its rules, in order` | a `condition` other than `gte` the number of steps, see [correlations](correlations.md#not-supported) |
| `correlation refers to unknown rules: x` | the rule was not among the paths you gave |
| `legacy rule collections ('action: global') are not supported` | old multi-document rule files |
| `missing 'detection' section` | the file is not a Sigma rule |
| `empty rule file` | nothing in the file |
| `invalid YAML: ...` | the parser's message follows |

A problem found while loading skips the whole file. In a file with a good rule and a
`temporal` correlation with a boolean condition, neither is converted:

```yaml
title: Good rule
name: good
detection:
  selection:
    EventID: 1
  condition: selection
---
title: Either order
correlation:
  type: temporal
  rules: [good]
  condition: good
```

```console
$ sigma2sql convert mixed.yml
skip mixed.yml: correlation 'condition' must be a map
```

Problems found later, such as a missing placeholder or a dialect limit, only skip that rule.

A regular expression is passed on as written, apart from its flags. sigma2sql does not rewrite
a pattern to fit a database; it reports the rule instead. On SigmaHQ's 3807 rules, this leaves
out three on PostgreSQL and none on the other databases
([how this is measured](correctness.md)).

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | every rule and correlation converted |
| `1` | at least one was skipped, or a path could not be read; the rest of the SQL is still printed |
| `2` | nothing to do, or bad input before any rule was read: no rule found, an unknown option or dialect, a bad profile, mapping or placeholders file |

```console
$ sigma2sql convert nothing.yml; echo $?
skip nothing.yml: [Errno 2] No such file or directory: 'nothing.yml'
1
$ sigma2sql convert empty; echo $?
sigma2sql: no .yml or .yaml files found
2
$ sigma2sql convert logon.yml -p nope; echo $?
sigma2sql: unknown profile 'nope' (built in: ecs-winlogbeat, evtx, ocsf, sysmon)
2
$ sigma2sql convert logon.yml -m badmap.yml; echo $?
sigma2sql: mapping: expected a map of field name to column name
2
```

A path that does not exist is a skip with code `1`. A directory with no rule files is code `2`.
