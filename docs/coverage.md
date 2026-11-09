# Rule coverage

A rule that needs a field your logs do not have never fires, and nothing tells you. `coverage`
reads a sample of your events, works out which fields they hold, and sorts your rules by whether
they can match at all.

It works on log files and on a [database](database.md), with the same options as `hunt`:

```bash
sigma2sql coverage sigma/rules --logs 'logs/*.evtx'
SIGMA2SQL_DSN=postgresql://reader@db/logs sigma2sql coverage sigma/rules -t logs --json-column event -p evtx
```

Run on the events in SigmaHQ's regression samples:

```console
$ sigma2sql coverage sigma/rules --logs 'regression_data/**/*.evtx'
Looked at the fields of 510 events.

  2,190  rules have every field they use
     32  rules can match but miss some fields
    205  rules can never match
    737  rules are for other log sources

 BLINDS  WEAKENS  MISSING FIELD
     28        1  Data
     24        0  ObjectName
     21       14  ImagePath
```

`BLINDS` is how many rules cannot match without that field, and `WEAKENS` how many can still
match but lose part of their logic. Start at the top: one field can bring back dozens of rules.
It may be missing because the source does not log it, or because a
[profile](profiles.md) does not map it to the right place.

`--format json` lists every rule with its status and missing fields.

## How a rule is judged

Missing fields are treated the way the generated SQL treats them. `a and b` needs both fields,
`a or b` needs one, and `not a` can still match when `a` is missing.

## Limits

- It looks at the first `--sample` events of each table, 10000 by default. A field that only
  appears later counts as missing, so use a larger sample on mixed tables.
- A field is judged present across the whole table. It does not check that the same event has
  every field a rule needs, or that a value can ever occur.
- Results are about fields only: a rule marked as ready can still have a value that never occurs.
