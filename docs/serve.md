# Local interface

`serve` opens a page on this machine that does the same work as the commands, without having to
remember the options:

```bash
sigma2sql serve sigma/rules
```

The page has three steps:

1. Choose the rules and where the logs are: files, or a [database](database.md).
2. See the [coverage](coverage.md) of your rules. For each missing field you can name the field
   of your logs that holds it, and check again. The page offers fields with a similar name, and
   shows the mapping as a profile you can keep and use with the commands.
3. Run the rules and read the [report](hunt.md#-html).

`--port` sets the port and `--no-browser` only prints the address.

## Safety

The page can hold a database password and shows text from logs an attacker may have written.

- It listens only on `127.0.0.1`. There is no option to open it to the network.
- Each start prints an address with a new secret. Without it every request is refused.
- Requests naming another host are refused, which stops DNS rebinding from another site, and
  forms carry the same secret.
- The pages run no script, and a Content Security Policy forbids scripts and outside requests.
- The database address is kept in memory only and is never written back to the page.

The settings and results last until you stop the command, and one job runs at a time.
