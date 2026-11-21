# keys

A small command-line tool for the owner's credentials that never prints, logs or writes a
credential's value. It reads values from 1Password in memory, passes them only on stdin or in a
child's environment, and prints names, fingerprints, dates and verdicts.

Work in progress: see [What is next](#what-is-next).

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
It exits 1 on any problem: no expiry, expired, a lifetime or age over 180 days, an expiry more
than 180 days away, no `kept_because`, or more kept credentials than `kept_budget`. From day 120
a credential shows as due, without failing. It reads only the mapping file, and never prints
its text fields.

```text
NAME       KIND        FP           EXPIRES     LEFT  LIFETIME  NOTES
app-mail   generic     fp:1a2b3c4d  2027-04-30  160   180
old-token  github-pat  -            -           -     -         no expiry; rotated 234 days ago, over 180; no kept_because

2 credentials kept, 1 with problems
```

## The canary tests

Every command's tests run through one harness, `tests/canary.py`. It plants a made-up value in
a fake 1Password and fake services, runs the command, and fails if the value reaches:

- stdout or stderr: the command's streams, Python's, and file descriptors 1 and 2, so a child
  that inherits the terminal is caught too;
- the text of an exception that escapes;
- any child process's argv or environment. An audit hook records every child as it starts, and
  any program that is not one of the harness's fakes on `PATH` fails the test. Piping the value
  to a child is allowed only for `op item create` and `op item edit`;
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
