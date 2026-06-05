# probe

![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)

**Logs your AI agent can investigate, not just read.**

probe turns large log files into a short, ranked summary your AI agent can read,
then lets the agent search the full logs on demand. It runs on your own machine.
It removes secrets before anything is sent to a model. There is no server to run
and no per-use cost.

## The problem

When something breaks, the logs that explain it are often too large to send to a
language model. A million log lines can cost more than twenty dollars to send to a
large model in one request, and most of those lines are routine. If you cut the logs
down to fit, you usually remove the few lines that actually matter.

## What probe does

probe reads the logs once and produces two things:

1. A short summary, which we call the capsule. It holds the log lines most likely to
   explain the incident, ranked by how relevant they are, with routine messages
   collapsed into counts. It is small enough to send to a model at low cost.
2. A full, searchable copy of the logs on disk. Nothing is thrown away. The agent can
   search it, read the lines around any event, follow a single request across services,
   and re-check any claim against the original lines.

The agent reads the summary first, then asks for more only where its question leads.
Every number in the summary can be traced back to real log lines.

probe does not guess a root cause for you. It surfaces ranked facts and clearly labeled
guesses, and leaves the conclusion to the agent or to you.

## Who it is for

Anyone whose AI agent needs to read logs:

- On-call engineers and site reliability engineers working through an incident.
- Security and platform teams that cannot send raw logs to an outside service.
- Teams in finance, healthcare, and government, where logs have to stay on their own
  machines.
- Anyone using an AI coding agent such as Claude Code or Cursor who wants it to read
  real production logs without a large bill.

## How it works

A single pass over the log file does all of the following:

1. Groups lines that belong together, so a stack trace stays as one record.
2. Finds the repeating shape of each line, so routine messages collapse into counts.
3. Compares each kind of line against the rest of the same file, so probe can flag what
   is new, what stopped happening, and what changed rate. This needs no prior history.
4. Ranks lines by how likely they are to explain the incident.
5. Removes secrets.
6. Saves a full, searchable copy on disk.

The summary and every search are views over that one saved copy, so investigating costs
almost no extra work.

## Install

```bash
./install.sh
```

This sets up an isolated environment and puts `probe` on your PATH. There are no runtime
dependencies. You can also run `./bin/probe` directly without installing, or use
`pip install .`.

## Quickstart

```bash
probe selftest                         # run the checks and a short demo
probe build /path/to/app.log           # prints the summary and a capture id

# then search the full logs:
probe search  <capture_id> --level ERROR --limit 20
probe context <capture_id> 85004 --before 5 --after 10
probe trace   <capture_id> <request_id>
probe verify  <capture_id> F12         # re-derive a fact from the original lines
```

You can also wrap any command your agent already runs and capture its output:

```bash
probe wrap -- kubectl logs api -n prod --tail=200000
probe wrap -- journalctl -u api --since "1 hour ago"
probe wrap -- docker compose logs api
```

## Use it with an AI agent (Model Context Protocol)

probe speaks the Model Context Protocol (MCP), so agents that support MCP, such as
Claude Code and Cursor, can call it directly. Add this to your MCP config:

```json
{
  "mcpServers": {
    "probe": { "command": "probe", "args": ["mcp"] }
  }
}
```

The agent gets these tools: `build`, `capsule`, `search`, `context`, `trace`, `verify`.
It reads the short summary first, then pulls more as its questions require. No model runs
inside probe. Your agent does the reasoning.

## What you get

Running `probe selftest` on a generated incident of 1.2 million log lines (a database
connection pool running out, buried in routine traffic, with a planted secret and a
heartbeat that goes quiet):

| measure | value |
|---|---|
| input | 1,200,000 lines |
| summary | about 1,740 tokens (the units a model is billed by) |
| build time | 8.8 seconds in Python on one core, under one second with the optional Rust build |
| cost to send the summary to a model | about half a cent, against roughly twenty dollars for the raw logs |

That 690 times figure is a best case on generated logs. On real service logs, expect the
summary to be about 40 to 56 times smaller than the input. On output where almost every
line is different, such as terminal dumps, there is little to collapse, so the ratio drops
to about 5 times, and probe tells you when that happens.

## probe compared to the alternatives

| | send raw logs to the model | hosted log-compression service | probe |
|---|---|---|---|
| where your logs go | to the model provider | to the service provider, then redacted | they stay on your machine |
| logs after the summary | not kept | discarded | kept and searchable |
| can the agent check a claim against the original lines | only if they fit | no | yes |
| works with no log history | yes | varies | yes |
| secrets | sent, then trusted to be redacted | sent, then redacted | removed before anything leaves |
| cost to run | high per request | a subscription that grows with use | nothing beyond the agent you already pay for |

## Security and privacy

- Logs stay on your machine. The only thing that can leave is the summary your agent
  chooses to send to its model, and secrets are removed from it first.
- probe removes common secrets before they can reach a model: passwords, API keys, cloud
  keys, tokens, private keys, credit card numbers (checked against the standard card
  checksum), social security numbers, and authorization headers. It keeps identifiers
  like request ids and commit hashes so that search still works. It errs toward removing
  too much rather than too little.
- The saved copy on disk is private to you. The cache folder and every file in it are
  created so that only your user account can read them, so other users on a shared machine
  cannot read your logs.
- A capture id is checked before any file path is built, so a crafted id cannot reach
  files outside the cache folder.
- Every time probe opens a saved capture, it checks the capture against its recorded
  fingerprint. A capture that was changed or damaged is refused rather than used.
- The summary marks log content as data, not instructions, so an agent reading it is less
  likely to act on text that an attacker planted in the logs.
- Honest limit: these protections cover other users on the same machine, accidental
  corruption, and tampering on disk. They do not stop software running as your own account
  or as an administrator, which can change both the data and its fingerprint. No tool that
  runs only on your machine can prevent that. Pair probe with the usual operating system
  controls for that case.

All of this is checked automatically by `probe selftest` and by the test suite for the
optional Rust build.

## How probe is built

probe is written in Python and uses only the standard library, so there is nothing to
install beyond Python itself. The part that does the heavy reading also has an optional
build in Rust that produces the same files and runs the same work several times faster.
probe uses the Rust build when it is present and falls back to Python otherwise.

The saved copy on disk keeps every original line. It records the repeating shape of each
line once and stores only what changes between lines, which makes it smaller than a plain
compressed file while still letting probe read any single part without unpacking the whole
thing. On the generated test it is about 34 times smaller at 100,000 lines and about 114
times smaller at 1.2 million lines, against about 17 times for a plain compressed copy. On
real logs the ratio is lower, and the figures here are reported as best cases on generated
data.

On a public collection of real-world logs, probe groups similar lines about as accurately
as widely used methods and labels them more precisely.

## Reproduce the numbers

```bash
probe selftest                            # the checks and the demo above
PYTHONPATH=. python3 -m bench.grouping     # grouping accuracy on a public log set
PYTHONPATH=. python3 -m bench.diagnosis    # the summary against raw logs and against plain counts
```

## Frequently asked questions

**Does probe send my logs to the cloud?**
No. probe runs on your machine. The only thing that can leave is the short summary, and
only when your agent decides to send it to its model. Secrets are removed from that
summary first.

**Does it need an API key or a logged-in account?**
No. probe does not call any model and does not need an account. Your AI agent is what talks
to a model, using whatever access you already have.

**Which models does it work with?**
Any of them. probe produces plain text. The reasoning is done by whatever agent or model
you use.

**How much does it cost to run?**
Nothing beyond the agent you already pay for. There is no server and no per-use charge. The
work happens on your computer.

**What log formats does it accept?**
Plain text logs, from a file or from a command's output. It does not need a fixed format.
It learns the repeating shapes from the file itself.

**Does it lose any log lines?**
No. The summary is short, but the full logs are kept on disk and stay searchable. Any fact
in the summary can be traced back to the original lines.

**Can I use it without an AI agent?**
Yes. The command line tools (`build`, `search`, `context`, `trace`, `verify`) work on their
own.

## License

MIT. See [LICENSE](LICENSE). You are free to use, change, and build on it.
