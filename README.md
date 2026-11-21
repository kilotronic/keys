# keys

A small command-line tool for the owner's credentials that never prints, logs or writes a
credential's value. It reads values from 1Password in memory, passes them only on stdin or in a
child's environment, and prints names, fingerprints, dates and verdicts.

Phase 1 of the design (list, check, scan, scrub and new), and from phase 2, sync. `keys list` and the `generic` kind
are additions to the design's lists. See [What is next](#what-is-next).

## The mapping file

One TOML file lists every credential and where it goes: names, 1Password item references,
targets, fingerprints and dates. Never a value. `--mapping PATH`, else `$KEYS_MAPPING`, else
`./keys.toml`.

```toml
kept_budget = 3                          # optional: most kept credentials allowed

[[credential]]
name = "app-mail"
kind = "generic"                         # github-app-key, github-pat, railway-project-token,
                                         # cloudflare-token, generic
item = "op://<vault>/<item title>"       # vault and item, no field
kept_because = "the mail provider has no OIDC sign-in"
fp = "1a2b3c4d"                          # keyed fingerprint, not secret
rotated = 2026-11-01
expires = 2027-04-30

[[credential.target]]
type = "railway"                         # also github-actions, github-actions-env,
service = "app"                          # github-actions-org, azure-key-vault, gcp-secret
environment = "production"
variable = "MAIL_API_KEY"
```

A mistake names the field and never repeats what it held, since a value pasted into the wrong
place would be printed back: `keys: credential[0] (app-mail).expires: must be a date`.

## Commands

### `keys list`

Every credential, its fingerprint, expiry, days left and lifetime, and what is wrong with it.
It exits 1 on any problem: no expiry, expired or expiring today, a lifetime or age over 180
days, an expiry more than 180 days away, a rotation date in the future or after the expiry, no
`kept_because`, more kept credentials than `kept_budget`, or no credentials at all. For a kind
whose provider cannot set an expiry (a GitHub App key, a Railway token, `generic`), the expiry
is 180 days after `rotated`. From day 120 a credential shows as due, without failing. It reads
only the mapping file and never prints its text fields, nor a path given to it (either could be
a value pasted in the wrong place).

```text
NAME       KIND        FP           EXPIRES     LEFT  LIFETIME  NOTES
app-mail   generic     fp:1a2b3c4d  2027-04-30  160   180
old-token  github-pat  -            -           -     -         no expiry; rotated 234 days ago, over 180; no kept_because

2 credentials kept, 1 with problems
```

### `keys check <service> --key <source>`

Asks the service that issued a key whether it still works, with one free, read-only call, and
prints one line: the service, the key's fingerprint, the hint the service's console shows, and
the verdict (WORKS, DEAD or UNKNOWN) with the HTTP status and the service's error code.

```text
$ keys check github --key op://<vault>/<item>/credential --expect dead
github key fp:3f9a1c02 github_p…Ab3d: DEAD (HTTP 401 from api.github.com/rate_limit)
```

- The key comes from `op://…` (read in memory through 1Password), `env:NAME` or `stdin`, never
  the command line. A source keys does not know is not repeated back.
- `fp:` is the first 8 hex digits of an HMAC-SHA-256 keyed by a fingerprint secret, from
  `--fp-key` or `$KEYS_FP_KEY` (same source forms), so a short key cannot be guessed from it.
- Nothing a service or a program says is passed through: only the status, an error code that
  holds no piece of the key, and for a network failure its type. When 1Password fails, only
  `op`'s exit code is shown. Programs keys starts see only a few basic variables of its
  environment, so a key handed to keys in a variable never reaches them.
- A key goes only over https (plain http only to this machine, never through a proxy), and a
  redirect is not followed, since following it would send the key on to wherever it points.
- `keys check --list` names the services. `http` covers any HTTPS API (`--url`, then
  `--header 'Name: {key}'`, `--bearer` or `--query NAME`).
- Exit 0 for WORKS (or the `--expect` verdict), 1 for DEAD (or the other), 2 for UNKNOWN, 3 for
  a usage error.

### `keys scan`

Searches the places an agent's or a shell's words are kept, all of them backed up and outliving
any key: `~/.claude` (transcripts, typed-prompt history, file history, shell snapshots, debug
logs), Claude's temp and scratch folders (`claude*` under `$TMPDIR`, `/tmp`, `/private/tmp`),
the Claude desktop app's logs and support folder, Cursor's agent folders, shell history, and
saved Terminal, iTerm2 and tmux state. `keys scan --paths` lists them; `--path` adds one.

Caches, disk images and editor extensions are skipped; `$HISTFILE` and `$ZDOTDIR` are
followed, and so is a root that is a symlink (a dotfiles manager's `~/.claude`).

Two passes over each file, read in overlapping 1 MB pieces. First every credential in the
mapping file, read in memory from 1Password and searched for as sent and in its URL-encoded,
JSON-escaped, base64 (also wrapped across lines), hex and UTF-16 forms, and with any backslash
escaping removed (JSON inside JSON, shell history); that catches what no pattern can, such as a
random signing secret. Then pattern rules for secret
shapes (GitHub, Anthropic, OpenAI, Slack, AWS, Google, Stripe and 1Password service-account
tokens, private keys). A finding names the file, the line and the credential or rule, never the
text it matched, and a file name that itself holds a value or a shape is withheld:

```text
~/.claude/projects/<project>/<session>.jsonl:412: app-mail (known value)
~/.zsh_history:9031: looks like github-token
keys scan: 18234 files, 2 findings
```

Exit 1 on any finding, 2 when the scan is incomplete (a value 1Password could not give, or a
file or folder it could not read), 0 when clean. It runs at about 9 MB/s with 30 credentials. `--patterns-only` skips 1Password.

The response to a finding: rotate that key (backups already hold it), then scrub the file.

### `keys scrub <file>`

Replaces every match in one text file (each known value in each form, the whole base64 run
around an encoded one, a whole private-key block, and each pattern match) with
`[removed by keys scrub]`. It rewrites the same file in place, so a program still writing to it
keeps one file, and refuses binary files (a database or saved state), which a rewrite would
break: for those, rotate the key and delete the file if nothing needs it. It prints only how
many it replaced. Nobody opens the file to redact it by hand, which would copy the value into a new
transcript.

### `keys new <kind> <name> --vault <vault> --kept-because <text>`

Makes the empty 1Password item for a credential, and adds its mapping entry. The item is an API
Credential titled `<kind> <name>`, tagged `keys` and the kind, with an empty concealed
`credential` field and the kind's other fields (an App's id, a token's id or owner), also empty.
It goes to `op` as JSON on stdin, never as `field=value` arguments. keys refuses a name or item
already in the mapping file, an item title already in the vault (in any case), and any flag
text shaped like a key, before anything is made. It creates only `./keys.toml`, never a missing
file named by `--mapping` or `$KEYS_MAPPING`. If `op` fails after saving the item, `--entry-only`
adds just the mapping entry.

```text
$ keys new cloudflare-token deploy --vault <vault> --kept-because "no OIDC sign-in for deploys"
made the 1Password item cloudflare-token deploy in <vault>, and added deploy to the mapping file
next: paste the value into its credential field in the 1Password app (never a terminal or a chat)
```

Kinds: `github-app-key`, `github-pat`, `railway-project-token`, `cloudflare-token`, `generic`.

### `keys sync <name> | --all [--dry-run]`

Writes the value in 1Password to every target the mapping file lists for that credential. The
value is read in process and handed to each target's own command line on its stdin, never its
arguments, a file or the terminal:

| Target               | Command                                                                          |
| -------------------- | -------------------------------------------------------------------------------- |
| `github-actions`     | `gh secret set NAME --repo R`                                                    |
| `github-actions-env` | `gh secret set NAME --repo R --env E`                                            |
| `github-actions-org` | `gh secret set NAME --org O --visibility selected --repos a,b` (or all, private) |
| `railway`            | `railway variable set KEY --stdin --skip-deploys --service S ...`                |
| `azure-key-vault`    | `az keyvault secret set --file /dev/stdin --tags keys-fp=<fp>`                   |
| `gcp-secret`         | `gcloud secrets versions add NAME --data-file=-`, then a `keys-fp` label         |

Railway variables are staged without a deploy; then each Railway service is redeployed once and
waited for, told apart from the old deployment by its id (`--no-deploy` skips that). Key Vault
and Secret Manager get the keyed fingerprint as a tag or label, so a later check can compare it
without the value. Each program sees only the basic variables of keys's environment and the few
of its own that sign it in or find its settings (`GH_TOKEN`, `GITHUB_TOKEN`, `GH_HOST`,
`GH_CONFIG_DIR`, `RAILWAY_TOKEN`, `RAILWAY_API_TOKEN`, `AZURE_CONFIG_DIR`, `CLOUDSDK_CONFIG`,
`GOOGLE_APPLICATION_CREDENTIALS` and a few more), never a debug, logging or telemetry switch,
and never the variable the fingerprint key came from.

Every target stores the same bytes: `gh` trims a value's trailing line breaks and `az` folds
CR LF, so keys refuses a value holding a carriage return and removes trailing line breaks
before any write, for every target alike. The fingerprint is of what the targets hold.

```text
$ keys sync app-mail
app-mail  github-actions owner/app MAIL_KEY  fp:1a2b3c4d  written
app-mail  railway app/production MAIL_API_KEY  fp:1a2b3c4d  written
app (production): deployed
keys sync: 2 targets written for 1 credential
```

- The first failure stops the sync, naming the target and how many were written before it. Run
  it again once the cause is fixed: writing the same value twice is harmless.
- A value whose fingerprint differs from the `fp` the mapping file records is refused without
  `--force`: 1Password was changed outside `keys rotate`, and writing it could replace a good
  value everywhere.
- Every target field goes on a program's command line, so each must be a plain name (a repo,
  a secret name); a field that is not, or looks like a key, is refused and not printed. A Railway
  project id is checked but never printed, since a UUID is also the shape of a Railway token.
- `--dry-run` reads nothing from 1Password and writes nothing: it names each target, whether
  the secret is there yet, and fails if a target cannot be listed.
- It needs the fingerprint key (`--fp-key` or `$KEYS_FP_KEY`), as `keys check` does.
- An organisation secret with `repos` is shared with those repos only; one without must say
  `visibility = "all"` or `"private"`, so a sync never widens or narrows who can read it.
- In Secret Manager, if the new version is added but its fingerprint label is not, the line
  says so and the sync exits 1: the value is in place, the label is stale.
- Built against the help of `railway` 5.71.0 (`variable set --stdin --skip-deploys`). Not yet
  proven against a real project: that a redeploy picks up variables staged with
  `--skip-deploys`, and that `railway deployment list --json` lists the newest first.

## Does this text look like a value?

One module, `keys.looks`, answers it for every place keys might repeat text. Text looks like a
value when it holds a control or unprintable character, a secret shape, a UUID, or a run of 24
or more characters with no space that mixes letters and digits. In a link the host is exempt,
but each piece of its path, query and fragment is held to the same rule.

Where the places differ, and why:

- **Credential names** (the mapping file and `keys new`) also fail when a dash-separated part is
  longer than 16 characters. A name that looks like a value is refused and never repeated in an
  error.
- **Field names** in a mapping error are named only when they are a near miss of a real field
  (a typo) and pass the rule whole. A `verify` key that mixes letters and digits for 24
  characters, such as `header_x_api_key_v2_2024abc`, is refused.
- **Target fields** in the mapping file (repos, secret names, services) go on a program's
  command line, so each must match its field's plain-name rule and pass the rule; a Railway
  project, often a UUID, is checked against its name rule but never printed.
- **Error codes** from a service are shown only when they are 60 plain characters or fewer and
  pass the rule.
- **File names** in a scan finding are split on `-`, `_` and `.`, and the long-run rule applies
  to each piece. Paths are built from words, dates, UUIDs and commit ids, so a UUID or a
  40-digit commit id counts as plain there, and so does macOS's random per-user temp folder
  (`/var/folders/<xx>/<folder>/`). Without that, every Claude transcript name would be withheld
  and there would be nothing to pass to `keys scrub`. Secret shapes and control characters are
  still withheld, and so is any name holding a known value.

## The canary tests

Every command's tests run through one harness, `tests/canary.py`. It plants a made-up value in
a fake 1Password and fake services, runs the command, and fails if the value reaches:

- stdout or stderr: the command's streams, Python's, and file descriptors 1 and 2, so a child
  that inherits the terminal is caught too;
- the text of an exception that escapes;
- any child process's argv or environment. An audit hook records every child as it starts, and
  any program that is not one of the harness's fakes on `PATH` fails the test. Piping the value
  to a child is allowed only for `op item create` and `op item edit`, and for each target's
  write command (`gh secret set`, `railway variable set`, `az keyvault secret set`,
  `gcloud secrets versions add`, `gcloud secrets create`), never with a debug or logging flag,
  and then only exactly one value 1Password holds, recording which target it landed on;
- any file: a write under the temp folder, or outside the temporary home and working folder,
  fails at once; after the run no file there may hold the value unless the test planted it and
  it is unchanged;
- the history of a real interactive `zsh` that ran the command (`canary.shell(...)`), where the
  `keys` process carries the same audit-hook watch.

It looks for the value as sent and in its base64 (any alignment, URL-safe, wrapped), hex, URL
encoded (either case), JSON-escaped, SHA-256, SHA-1 and MD5 forms, any 9-character piece of it,
and any 12-character piece of an encoded form. A hint (the first 8 and last 4 characters) is
allowed only for a value the test marks provider-issued, since `keys` prints one only for keys a
provider issued, as the provider's console does.

## What is next

Phase 2, from the design:

- `keys rotate <name>`: the eight steps (preflight, create, probe, store, sync, verify, revoke,
  record), resuming after the owner's paste, with rollback until the old key is revoked. Takes
  over the Railway, signing-secret, datastore and Twilio rotation of the script it replaces.
- Revoke by API where the provider has one; otherwise open the provider's page for the owner.
- `keys check --all [--deep]` against the targets: in sync, unmapped secrets, and 1Password items
  not updated in 180 days; `keys fp <name>`.
- The gitleaks pass in `keys scan`, with the shared secret-scan rules and `--redact`, and a
  scan of only the files changed since the last run, for speed.
- `keys rotate --dry-run` and `--now`.
- The design's other starting kinds: `railway-workspace-token`, `openai-key`, `resend-key`,
  `twilio-key`, `azure-app-secret`, and `generated` (a random signing secret, with `mint`).
- Probes for Railway, Resend and Twilio, and the old checker's Key Vault and gitleaks-report
  sources, so the old scripts can become thin shims and then be deleted.
- The schedules: the nightly CI run with an issue from day 120, and a daily launchd `keys scan`
  on the Mac.
- A check, once, that `op item create` keeps the empty non-secret fields `keys new` asks for
  (`op item create --dry-run` previews without saving).
