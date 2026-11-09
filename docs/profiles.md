# Profiles

A profile says where your events keep Sigma's fields and which events each log source covers.
It is a small YAML file. `convert`, `hunt`, `test` and `check` all take one with `-p`, either
by built-in name or as a path:

```bash
sigma2sql convert rules/ -d postgres --json-column data -p evtx
sigma2sql check rules/ -p ./acme.yml
```

Without a profile each Sigma field is a column (or a top-level JSON key) of the same name, and
rules are not limited by log source: a network rule can then match a process event that
happens to have the same field values.

A value with a `.yml` or `.yaml` suffix is always read as a file. Any other value is read as a
file if one of that name exists, and is a built-in name otherwise. So a file called `sysmon`
in the working directory hides the built-in profile.

## Built-in profiles

```console
$ sigma2sql profiles
ecs-winlogbeat  Windows events shipped by Winlogbeat in Elastic Common Schema (nested JSON); unmapped fields fall back to winlog.event_data
evtx            Windows event logs exported to JSON by evtx_dump or python-evtx (Event.System / Event.EventData)
ocsf            OCSF 1.x events (nested JSON, time in epoch milliseconds), routed by class_uid
sysmon          Sysmon events with their original field names; each Sigma category is limited to its Sysmon event ID
```

| Profile | Layout | Event time | `product` | Fallback for unmapped fields |
| --- | --- | --- | --- | --- |
| `sysmon` | flat | `UtcTime` | `windows` | none |
| `evtx` | nested | `Event.System.TimeCreated.#attributes.SystemTime` | `windows` | `Event.EventData.{field}`, then `Event.EventData.{field_words}` |
| `ecs-winlogbeat` | nested | `@timestamp` | `windows` | `winlog.event_data.{field}` |
| `ocsf` | nested | `time`, epoch milliseconds | none | none |

No built-in profile names a JSON column, because that depends on your table. `hunt` over
files, `test` and `check` have their own, but `convert` and [`hunt` in a
database](database.md) need `--json-column` with the nested profiles. Without it a dotted path
becomes one column name, which is rarely what you want. `reg.yml` is shown
[below](#field-lookup):

```console
$ sigma2sql convert reg.yml -p evtx
-- Value set by reg.exe
SELECT * FROM "events" WHERE (("Event.System.Channel" = 'Microsoft-Windows-Sysmon/Operational' COLLATE NOCASE AND "Event.System.EventID" = 13) AND ("Event.EventData.Image" LIKE '%\\reg.exe' ESCAPE '\' AND COALESCE("Event.EventData.NewValue", "Event.EventData.New Value") = 'evil' COLLATE NOCASE));

$ sigma2sql convert reg.yml -p evtx --json-column data
-- Value set by reg.exe
SELECT * FROM "events" WHERE ((json_extract("data", '$."Event"."System"."Channel"') = 'Microsoft-Windows-Sysmon/Operational' COLLATE NOCASE AND CAST(json_extract("data", '$."Event"."System"."EventID"') AS TEXT) = '13') AND (json_extract("data", '$."Event"."EventData"."Image"') LIKE '%\\reg.exe' ESCAPE '\' AND COALESCE(json_extract("data", '$."Event"."EventData"."NewValue"'), json_extract("data", '$."Event"."EventData"."New Value"')) = 'evil' COLLATE NOCASE));
```

### sysmon

For Sysmon events that keep their own field names at the top level, so nothing is mapped. The
profile only limits each Sigma category to its event ID:

| Category | `EventID` | Category | `EventID` |
| --- | --- | --- | --- |
| `process_creation` | 1 | `registry_set` | 13 |
| `file_change` | 2 | `registry_rename` | 14 |
| `network_connection` | 3 | `registry_event` | 12, 13, 14 |
| `process_termination` | 5 | `create_stream_hash` | 15 |
| `driver_load` | 6 | `pipe_created` | 17, 18 |
| `image_load` | 7 | `wmi_event` | 19, 20, 21 |
| `create_remote_thread` | 8 | `dns_query` | 22 |
| `raw_access_thread` | 9 | `file_delete` | 23, 26 |
| `process_access` | 10 | `clipboard_capture` | 24 |
| `file_event` | 11 | `process_tampering` | 25 |
| `registry_add` | 12 | `file_executable_detected` | 29 |
| `registry_delete` | 12 | | |

Every entry needs `product: windows` on the rule as well. Rules for a `service`, such as
`security`, get no extra condition.

### evtx

For Windows events as `evtx_dump` or python-evtx export them to JSON. This is the layout `hunt`
produces from `.evtx` files, and it uses this profile by itself when you pass no other
([details](hunt.md)).

| Sigma field | Path in the event |
| --- | --- |
| `EventID` | `Event.System.EventID.#text`, then `Event.System.EventID` |
| `Channel` | `Event.System.Channel` |
| `Computer` | `Event.System.Computer` |
| `Provider_Name` | `Event.System.Provider.#attributes.Name` |
| `Level` | `Event.System.Level` |
| `Keywords` | `Event.System.Keywords` |
| `Operation` | `Event.EventData.Operation`, then under `Event.UserData.Operation_ClientFailure` and `Event.UserData.Operation_StartedOperational` |
| `ClientMachine`, `PossibleCause` | `Event.EventData`, then `Event.UserData.Operation_ClientFailure` |
| `Consumer` | `Event.EventData.Consumer`, then `Event.UserData.Operation_ESStoConsumerBinding.CONSUMER` |
| `Query` | `Event.EventData.Query`, then `Event.UserData.Operation_TemporaryEssStarted.Query` |

Every other field is read from `Event.EventData`. `EventID` has two paths because it carries
Qualifiers on some logs and then becomes an object with a `#text` key. The `{field_words}`
fallback exists for Defender, which writes `New Value` for `NewValue`, and the `UserData`
paths for WMI-Activity. Both came out of the
[regression samples](correctness.md#regression-samples).

The log sources:

- The 23 Sysmon categories in the table above, each limited to the channel
  `Microsoft-Windows-Sysmon/Operational` and its event ID.
- `ps_script` (4104) and `ps_module` (4103) on `Microsoft-Windows-PowerShell/Operational`;
  `ps_classic_start` (400) and `ps_classic_provider_start` (600) on `Windows PowerShell`.
- Services, each limited to its channel:

| Service | `Event.System.Channel` |
| --- | --- |
| `security`, `system`, `application` | `Security`, `System`, `Application` |
| `sysmon` | `Microsoft-Windows-Sysmon/Operational` |
| `powershell` | `Microsoft-Windows-PowerShell/Operational` |
| `powershell-classic` | `Windows PowerShell` |
| `taskscheduler` | `Microsoft-Windows-TaskScheduler/Operational` |
| `wmi` | `Microsoft-Windows-WMI-Activity/Operational` |
| `windefend` | `Microsoft-Windows-Windows Defender/Operational` |
| `bits-client` | `Microsoft-Windows-Bits-Client/Operational` |
| `firewall-as` | `Microsoft-Windows-Windows Firewall With Advanced Security/Firewall` |
| `appxdeployment-server` | `Microsoft-Windows-AppXDeploymentServer/Operational` |
| `codeintegrity-operational` | `Microsoft-Windows-CodeIntegrity/Operational` |
| `dns-client` | `Microsoft-Windows-DNS Client Events/Operational` |
| `driver-framework` | `Microsoft-Windows-DriverFrameworks-UserMode/Operational` |
| `ntlm` | `Microsoft-Windows-NTLM/Operational` |
| `terminalservices-localsessionmanager` | `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` |
| `openssh` | `OpenSSH/Operational` |

### ecs-winlogbeat

For Windows events shipped by Winlogbeat in Elastic Common Schema. Fields without an ECS home
fall back to `winlog.event_data`.

| Sigma field | ECS field |
| --- | --- |
| `EventID` | `event.code` |
| `Channel` | `winlog.channel` |
| `Provider_Name` | `winlog.provider_name` |
| `Computer` | `host.name` |
| `Image` | `process.executable` |
| `CommandLine` | `process.command_line` |
| `ProcessId` | `process.pid` |
| `CurrentDirectory` | `process.working_directory` |
| `OriginalFileName` | `process.pe.original_file_name` |
| `Product`, `Company`, `Description` | `process.pe.product`, `.company`, `.description` |
| `ParentImage` | `process.parent.executable` |
| `ParentCommandLine` | `process.parent.command_line` |
| `ParentProcessId` | `process.parent.pid` |
| `User` | `user.name` |
| `TargetFilename`, `ImageLoaded` | `file.path` |
| `DestinationIp`, `DestinationPort` | `destination.ip`, `destination.port` |
| `DestinationHostname` | `destination.domain` |
| `SourceIp`, `SourcePort` | `source.ip`, `source.port` |
| `QueryName` | `dns.question.name` |
| `TargetObject` | `registry.path` |

The Sysmon categories assume the Winlogbeat sysmon module, where `event.code` holds the event
ID as a string. Each category is also limited to the channel
`Microsoft-Windows-Sysmon/Operational`:

| Log source | Condition |
| --- | --- |
| `process_creation` | `event.code` 1 |
| `network_connection` | `event.code` 3 |
| `image_load` | `event.code` 7 |
| `process_access` | `event.code` 10 |
| `file_event` | `event.code` 11 |
| `registry_set` | `event.code` 13 |
| `registry_event` | `event.code` 12, 13 or 14 |
| `dns_query` | `event.code` 22 |
| service `security` | `winlog.channel` is `Security` |
| service `system` | `winlog.channel` is `System` |
| service `powershell` | `winlog.channel` is `Microsoft-Windows-PowerShell/Operational` |

### ocsf

For OCSF 1.x events, with the time in epoch milliseconds in `time`.

| Sigma field | OCSF field |
| --- | --- |
| `Image` | `process.file.path` |
| `CommandLine` | `process.cmd_line` |
| `ProcessId` | `process.pid` |
| `CurrentDirectory` | `process.file.parent_folder` |
| `ParentImage` | `actor.process.file.path` |
| `ParentCommandLine` | `actor.process.cmd_line` |
| `ParentProcessId` | `actor.process.pid` |
| `User` | `actor.user.name` |
| `Computer` | `device.hostname` |
| `TargetFilename` | `file.path` |
| `DestinationIp`, `DestinationPort` | `dst_endpoint.ip`, `dst_endpoint.port` |
| `DestinationHostname` | `dst_endpoint.hostname` |
| `SourceIp`, `SourcePort` | `src_endpoint.ip`, `src_endpoint.port` |
| `QueryName` | `query.hostname` |

| Category | Condition |
| --- | --- |
| `process_creation` | `class_uid` 1007 and `activity_id` 1 |
| `file_event` | `class_uid` 1001 |
| `network_connection` | `class_uid` 4001 |
| `dns_query` | `class_uid` 4003 |

These entries match on the category alone and the profile sets no `product`, so `hunt` runs
every rule with this profile.

## Write your own

```yaml
# acme.yml
description: Our Windows events
json_column: event                       # for convert and hunt in a database
nested: true                             # dotted names are paths into nested JSON
timestamp: ts                            # event time for correlations
timestamp_format: epoch_s                # iso (default), epoch_s or epoch_ms
product: windows                         # hunt runs only rules for this product
default_field: ["attrs.{field}", "attrs.{field_words}"]
fields:
  Image: [proc.path, proc.image]         # first one present wins
logsources:
  - match: {product: windows, category: registry_set}
    table: registry_events               # for convert and hunt in a database
    where: {kind: set}
  - match: {product: windows}
    where: {source|startswith: win}
```

Every key is optional, and an empty file is a valid profile.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `description` | string | empty | The line `sigma2sql profiles` shows for a built-in profile |
| `json_column` | string | none | JSON column to read from; without it each field is a column |
| `nested` | boolean | `false` | Split names on dots and follow them into nested JSON |
| `timestamp` | string | `timestamp` | Column or path of the event time, see [Event time](#event-time) |
| `timestamp_format` | string | `iso` | `iso`, `epoch_s` or `epoch_ms` |
| `product` | string | none | See [product scoping](#product-scoping) |
| `default_field` | string or list | none | Templates for fields not in `fields` |
| `fields` | map | empty | Sigma field to a name, or a list of names |
| `logsources` | list | empty | See [log sources](#log-sources) |

There is no top-level `table`: the table comes from `-t` or from a `logsources` entry.

## Field lookup

Each Sigma field is looked up in this order, and the first step that knows the field decides:

1. The `-m` mapping file.
2. The profile's `fields`.
3. The profile's `default_field` templates.
4. The field's own name.

The event time has an order of its own, see [Event time](#event-time).

A list in `fields` and several `default_field` templates both give a chain of candidates, which
becomes `COALESCE`. The first one that is not NULL wins, so a key that is present with a JSON
`null` falls through to the next.

In a template, `{field}` is the Sigma name and `{field_words}` the same name with a space
before each capital that follows a lower-case letter or a digit: `NewValue` becomes `New Value`
and `IPAddress` stays as it is. Every template must contain one of the two.
When both templates give the same name, as they do for `Image`, it is used once.

With `acme.yml` from above, `Image` comes from the list in `fields` and `NewValue` from the
two templates:

```yaml
# reg.yml
title: Value set by reg.exe
logsource: {product: windows, category: registry_set}
detection:
  sel:
    Image|endswith: '\reg.exe'
    NewValue: evil
  condition: sel
```

```console
$ sigma2sql convert reg.yml -d postgres -p acme.yml
-- Value set by reg.exe
SELECT * FROM "registry_events" WHERE (LOWER("event"->>'kind') = 'set' AND (COALESCE("event"#>>'{"proc","path"}', "event"#>>'{"proc","image"}') ILIKE '%\\reg.exe' ESCAPE '\' AND LOWER(COALESCE("event"#>>'{"attrs","NewValue"}', "event"#>>'{"attrs","New Value"}')) = 'evil'));
```

### The `-m` mapping file

`-m` is a flat YAML map from Sigma field to your column or key, applied over the profile. It
is the place for the few fields that differ in your data. Each value must be one string; a
list is only allowed in a profile's `fields`.

```yaml
# mapping.yml
Image: exe_path
```

```console
$ sigma2sql convert reg.yml -p acme.yml -m mapping.yml
-- Value set by reg.exe
SELECT * FROM "registry_events" WHERE (json_extract("event", '$."kind"') = 'set' COLLATE NOCASE AND (json_extract("event", '$."exe_path"') LIKE '%\\reg.exe' ESCAPE '\' AND COALESCE(json_extract("event", '$."attrs"."NewValue"'), json_extract("event", '$."attrs"."New Value"')) = 'evil' COLLATE NOCASE));
```

`Image` now reads `exe_path` and the other field is unchanged. With `nested`, a mapped name is
still split on dots. The mapping does not reach the `where` of a log source, which is already
in your own field names.

## Event time

Correlations read the event time from the path `timestamp` names. `timestamp_format` says
how to read it: `iso` for text such as `2026-11-01T03:12:01Z`, `epoch_s` and `epoch_ms` for
numbers. The `minute` to `year` modifiers use the same format on the field they are written
on. `--timestamp-field` and `--timestamp-format` override both keys.

The time is read in this order, and the first step that knows the field decides:

1. An entry for the time field in the `-m` mapping file or the profile's `fields`.
2. The path `timestamp` names and then, with a JSON column, the `default_field` templates. These
   candidates become `COALESCE`, as for any field.

With this profile and a JSON column, the time is read from `ts`, then from `attrs.ts`:

```yaml
default_field: "attrs.{field}"
timestamp: ts
```

Without a JSON column only the templates apply, so the same profile reads the column `attrs.ts`.

The full path in a built-in profile comes first, so `default_field` does not move it. Here
`failed.yml` asks for three failed logons in five minutes, and `evtx.jsonl` holds three such
events in the `evtx` layout:

```console
$ sigma2sql hunt failed.yml --logs evtx.jsonl -p evtx -e 1
LEVEL         HITS  RULE
high             1  Repeated failed logons  (failed.yml)
                      {"TargetUserName":"admin","window_start":"2026-11-01 03:12:00","window_end":"2026-11-01 03:12:02","value":3}
1 of 1 rules matched 3 events (0 rules skipped)
```

An entry in `fields` or `-m` wins over both. `moved.jsonl` holds the same events with the time
in `Event.EventData.LogonTime`:

```yaml
# moved.yml
"Event.System.TimeCreated.#attributes.SystemTime": Event.EventData.LogonTime
```

```console
$ sigma2sql hunt failed.yml --logs moved.jsonl -p evtx
0 of 1 rules matched 3 events (0 rules skipped)

$ sigma2sql hunt failed.yml --logs moved.jsonl -p evtx -m moved.yml -e 1
LEVEL         HITS  RULE
high             1  Repeated failed logons  (failed.yml)
                      {"TargetUserName":"admin","window_start":"2026-11-01 03:12:00","window_end":"2026-11-01 03:12:02","value":3}
1 of 1 rules matched 3 events (0 rules skipped)
```

`--timestamp-field` follows the same order. With `-p evtx` a name such as `LogonTime` or
Sysmon's `UtcTime` is enough, as the `default_field` templates lead to `Event.EventData`:

```console
$ sigma2sql hunt failed.yml --logs moved.jsonl -p evtx --timestamp-field LogonTime -e 1
LEVEL         HITS  RULE
high             1  Repeated failed logons  (failed.yml)
                      {"TargetUserName":"admin","window_start":"2026-11-01 03:12:00","window_end":"2026-11-01 03:12:02","value":3}
1 of 1 rules matched 3 events (0 rules skipped)
```

## Log sources

Each `logsources` entry has a `match` map and can have a `table` and a `where`.

- **`match`** applies when every key in it is on the rule's `logsource` with the same value.
  The case of the value does not matter, but the key must be spelled as in the rule. An empty
  map applies to every rule.
- **The first entry that applies wins.** The others are not looked at, so put specific entries
  before general ones.
- **`where`** is a Sigma search map, added to the rule with `AND`. It can use lists (any of the
  values) and modifiers. Its keys are your own field names, as they are in the event: neither
  `fields`, `default_field` nor `-m` applies to them. `nested` and the JSON column do.
- **`table`** sends the rule to another table. `convert` and [`hunt` in a
  database](database.md) use it. `hunt` over files, `test` and `check` keep all events in one
  table, and still apply `where`.
- **A rule that no entry matches** runs on the default table with no extra condition.

In `acme.yml`, `reg.yml` took the first entry: table `registry_events` and `kind = 'set'`. A
rule for `service: security` falls through to the second entry:

```console
$ sigma2sql convert other.yml -p acme.yml
-- Any Windows rule
SELECT * FROM "events" WHERE (json_extract("event", '$."source"') LIKE 'win%' ESCAPE '\' AND CAST(COALESCE(json_extract("event", '$."attrs"."EventID"'), json_extract("event", '$."attrs"."Event ID"')) AS TEXT) = '4688');
```

## Product scoping

`product` tells `hunt` that the logs only hold this `logsource.product`, so it leaves out rules
for anything else. Without it, a rule of the form `not <address range>` for another product
matches every event, because the field it tests is missing and
[`not` on a missing field is true](features.md#null-and-missing-fields). Here the Zeek rule
is `not` a network range, and the log holds one Windows event:

```console
$ sigma2sql hunt zeek.yml win.yml --logs events.jsonl
LEVEL         HITS  RULE
-                1  Traffic outside the private range  (zeek.yml)
-                1  Windows logon  (win.yml)
2 of 2 rules matched 1 events (0 rules skipped)

$ sigma2sql hunt zeek.yml win.yml --logs events.jsonl -p sysmon
LEVEL         HITS  RULE
-                1  Windows logon  (win.yml)
1 of 1 rules matched 1 events (0 rules skipped)
1 rules are for other log sources
```

The comparison ignores case. A rule with no `product` at all is also left out. A correlation
stays if at least one of the rules it refers to has the product. With the three Windows
profiles a directory of all SigmaHQ rules can be used as it is.

Only `hunt` scopes by product. `convert`, `test` and `check` take the rules you give them.

## Options and profiles together

| Setting | What wins |
| --- | --- |
| Field names | `-m` over `fields` |
| Event time | `--timestamp-field` and `--timestamp-format` over the profile |
| `nested` | On if either the profile or `--nested` says so; there is no option to turn it off |
| JSON column on `convert` and `hunt` in a database | `--json-column` over the profile's `json_column` |
| Table on `convert` and `hunt` in a database | A log source's `table` over `-t` |
| Table and JSON column on `hunt` over files, `test`, `check` | Their own, whatever the profile says |

## Errors

An unknown profile name or key stops the command before any rule runs, with exit code 2:

```console
$ sigma2sql convert reg.yml -p sysmn
sigma2sql: unknown profile 'sysmn' (built in: ecs-winlogbeat, evtx, ocsf, sysmon)

$ sigma2sql convert reg.yml -p typo.yml
sigma2sql: unknown profile keys: default_fields
```

The same goes for a file that cannot be read or is not valid YAML, a `fields` that is not a map,
a list in `fields` that is empty or holds anything but strings, a `default_field` without
`{field}` or `{field_words}`, a `timestamp_format` other than the three above, a `logsources`
entry without a `match` map, a `where` that is not a map, and a `-m` file that is not a flat
map of strings.
