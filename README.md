# keys

A small command-line tool for the owner's credentials that never prints, logs or writes a
credential's value. It reads values from 1Password in memory, passes them only on stdin or in a
child's environment, and prints names, fingerprints, dates and verdicts.

Phase 1 of the design (list, check, scan, scrub and new), and from phase 2, sync, check --all,
rotate, fp and leaks (the last two taken over from the old key checker). `keys list` and the
`generic` kind are additions to the design's lists. See [What is next](#what-is-next).

## The mapping file

One TOML file lists every credential and where it goes: names, 1Password item references,
targets, fingerprints and dates. Never a value. `--mapping PATH`, else `$KEYS_MAPPING`, else
`./keys.toml`.

```toml
kept_budget = 3                          # optional: most kept credentials allowed
ignore_unmapped = ["DATA_LEAK_DENYLIST"] # optional: secrets at mapped scopes that are not credentials

[[credential]]
name = "app-mail"
kind = "generic"                         # github-app-key, github-pat, railway-project-token,
                                         # railway-workspace-token, cloudflare-token,
                                         # resend-key, twilio-key, generic
item = "op://<vault>/<item title>"       # vault and item, no field
kept_because = "the mail provider has no OIDC sign-in"
fp = "1a2b3c4d"                          # keyed fingerprint, not secret
rotated = 2026-11-01
expires = 2027-04-30
# minted_by = "mail-admin"               # keys rotate: the credential whose key mints this one
# permissions = { contents = "read" }    # github-pat: the levels its creation page pre-fills

[[credential.target]]
type = "railway"                         # also github-actions, github-actions-env,
service = "app"                          # github-actions-org, azure-key-vault, gcp-secret
environment = "production"
variable = "MAIL_API_KEY"
# field = "key_sid"                      # optional: send this non-secret field of the item
                                         # instead of the key (a Twilio key's SID); GitHub
                                         # and Railway targets only
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

- The key comes from `op://…` (read in memory through 1Password), `kv://<vault>/<secret>` (read
  in memory through `az keyvault secret show` under the owner's az sign-in), `env:NAME`, `stdin`,
  or `gitleaks:<report.json>#<fingerprint>` (the one leaked value in an unredacted gitleaks
  report whose keyed fingerprint starts with those digits, so a leaked key can be proved dead
  without anyone handling it), never the command line. A source keys does not know is not
  repeated back. The fingerprint secret takes only `op://…`, `env:NAME` or `stdin`.
- `fp:` is the first 8 hex digits of an HMAC-SHA-256 keyed by a fingerprint secret, from
  `--fp-key` or `$KEYS_FP_KEY` (same source forms), so a short key cannot be guessed from it.
- Nothing a service or a program says is passed through: only the status, an error code that
  holds no piece of the key, and for a network failure its type. When 1Password fails, only
  `op`'s exit code is shown. Programs keys starts see only a few basic variables of its
  environment, so a key handed to keys in a variable never reaches them.
- A key goes only over https (plain http only to this machine, never through a proxy), and a
  redirect is not followed, since following it would send the key on to wherever it points.
- `keys check --list` names the services. `http` covers any HTTPS API (`--url`, then
  `--header 'Name: {key}'`, `--bearer` or `--query NAME`). Added in phase 2: `github-app` (an
  App's private key signs a JWT, `--client-id`, and reads `GET /app`), `twilio` (`--user` the
  key's SID, `--account` the account SID), `railway-project` and `railway` (a workspace or
  account token), the last two read from Railway's GraphQL answer, which is 200 either way.
- **Why the App's JWT is signed in pure Python.** The design keeps keys to the standard library
  so the tool that holds every key pulls in no third-party code. RS256 signing is small
  (`keys.appjwt`: read the PEM, pad the digest as PKCS#1 v1.5 says, raise it to the private
  exponent) and nothing here verifies or decrypts, which is where hand-written RSA goes wrong;
  its tests check the signature with the RSA equation and with `openssl`.
- Exit 0 for WORKS (or the `--expect` verdict), 1 for DEAD (or the other), 2 for UNKNOWN, 3 for
  a usage error.

### `keys fp <name>` and `keys fp --key <source>`

The keyed fingerprint of a mapped credential's value, read from 1Password in memory, and for a key
a provider issued the hint its console shows; then whether it matches the mapping file's `fp`
(exit 1 when it differs). `--key` takes any source `keys check` takes and prints only `fp:`, and
with `--hint` also the start and end a provider's console shows (only for a key a provider issued).

```text
$ keys fp deploy
deploy cloudflare-token fp:1a2b3c4d Ab3dEf6h…Wx3Q: matches the mapping file
$ keys fp --key kv://app-kv/mail-key
fp:9c0e7d21
```

### `keys leaks <report.json>`

One line per distinct leaked value in a gitleaks JSON report made without `--redact`: its keyed
fingerprint, the rule, the first file (and how many more), how many findings and commits, the
first commit and the date range. Never the `Secret`, `Match` or `Line` fields; a file name, rule,
commit or date that looks like a value, or holds a piece of a leaked one, is withheld. A
redacted report is refused (it holds nothing to fingerprint). Exit 1 when the report holds any
leak. Then `keys check <service> --key gitleaks:<report.json>#<fp> --expect dead` for each, and
delete the report.

```text
$ keys leaks report.json
fp:3f9a1c02  github-pat  src/settings.py (+2 more)  4 findings in 3 commits, first 1a2b3c4d, 2025-01-02..2025-03-04
keys leaks: 1 leaked value in 4 findings
```

### `keys check --all [--deep]`

Every credential at every target. `--all` is the nightly CI check: it never starts 1Password and
needs no fingerprint key or any value. It prints what `keys list` prints, then one line per
target:

- GitHub (repo, environment, organisation): the secret is there by name, and its update date is
  not before the credential's `rotated` date (GitHub cannot be read back, so the date stands
  for the value). GitHub's date is UTC and `rotated` is the owner's own day, so one day of slack
  is allowed: a sync just after midnight east of UTC never fails, and a secret synced up to a
  day before the rotation passes. A secret with no update date, or a credential with no
  `rotated`, is a problem;
- Key Vault and Secret Manager: the secret is there (in Key Vault, enabled and not expired), and
  the `keys-fp` tag or label `keys sync` wrote equals the mapping file's `fp`; a credential with
  no `fp` is a problem, since nothing could be compared. Whether a Secret Manager secret has an
  enabled version is not checked (its listing does not say);
- Railway: skipped, since any listing of its variables holds their values (checked with
  `--deep`);
- any secret at a mapped repo, environment, organisation, vault or project that no mapping row
  names. A name that is not a credential (a CI setting held as a secret) goes in the mapping
  file's `ignore_unmapped = ["NAME", ...]`, which applies at every scope. Railway variables are
  not checked for this (most are settings, not secrets), nor are Key Vault secrets that back a
  certificate. GitHub and Key Vault names compare without regard to case, as those stores do.

A credential whose targets are all Railway is named with a note, since `--all` checks none of
them; the summary counts the skipped targets.

`--deep` is for the Mac. It needs the fingerprint key, reads each value from 1Password in process
and compares its keyed fingerprint with the mapping file's, reads each Railway variable in process
and compares it with 1Password's, compares every tag and label with the real value, and lists
every 1Password item tagged `keys` (names and dates only): each must be in the mapping file and
updated within 180 days, which catches an item rotated by hand, and each mapped item must carry
the tag. When a value cannot be read from 1Password, Railway's is compared with the mapping
file's `fp` instead.

```text
$ keys check --all --mapping keys/mapping.toml
NAME      KIND     FP           EXPIRES     LEFT  LIFETIME  NOTES
app-mail  generic  fp:1a2b3c4d  2027-04-30  160   180       expiry from rotation

1 credential kept, no problems

app-mail  github-actions owner/app MAIL_KEY  present
app-mail  github-actions-env owner/app env:production MAIL_KEY  updated 2026-10-15, before it was rotated on 2026-11-01
app-mail  azure-key-vault app-kv mail-key  present, fingerprint tag matches
app-mail  railway app/production MAIL_API_KEY  skipped: Railway is checked with --deep
-  github-actions owner/app  STRAY_TOKEN: not in the mapping file
keys check --all: 1 credential, 4 targets (1 skipped), 2 problems
```

Exit 0 when clean, 1 on any problem, 3 for a usage error. A scope keys cannot list (no sign-in,
no permission) is a problem: a check that cannot look must not pass. A store's error text is
never shown, only the program and its exit code; a secret name read from a store that is not a
plain name, or looks like a value, is printed as `<name withheld>`. In CI, `gh` signs in with
`GH_TOKEN`, which needs read access to the repos' secrets and environments (and the
organisation's secrets, for an org target).

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

Kinds: `github-app-key` (fields `app_id`, `client_id`, `slug`), `github-pat`,
`railway-project-token` (`project_id`, `environment_id`, `token_id`), `railway-workspace-token`,
`cloudflare-token`, `resend-key`, `twilio-key` (`key_sid`, `account_sid`) and `generic`.

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

A target with `field = "<name>"` gets that non-secret field of the item instead of the key,
read the same way (`op read op://<vault>/<item>/<name>`): a Twilio key's SID goes next to its
secret, and both change together in a rotation.

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

### `keys rotate <name> [--dry-run] [--now]`

Replaces a credential end to end, in the design's eight steps, and stops at the first failure:

1. **Preflight.** Every target can be reached, each GitHub Environment target admits `main` only
   (custom branch policies naming just `main`), and the 1Password item and the minting key can
   be read.
2. **Create.** A key keys can mint (Cloudflare, Resend) is made by API with the key of the
   credential named by `minted_by`, named `<name> <yyyy-mm-dd>`, and saved at once in the item's
   `pending` field; if that save fails it is revoked at once, since it exists nowhere else. For a
   GitHub personal token, which no API makes, keys opens GitHub's pre-filled page (name, owner,
   `expires_in=180`, the `permissions` from the mapping file) and the 1Password item, prints the
   repositories to pick, and exits 5. The owner pastes the token into the item's `pending` field
   (never a terminal or a chat) and runs `keys rotate <name>` again, which clears the clipboard
   and continues.
3. **Probe.** The new key must work, and where the provider sets an expiry, end within 180 days
   (GitHub's token-expiry header). If not, it is revoked (or its page opened) and `pending` is
   cleared.
4. **Store.** The current key moves to `previous`, the new one to the main field, in one save.
5. **Sync** to every target, as `keys sync` does.
6. **Verify.** A GitHub secret's update date moved; with `verify = { workflow = "deploy.yml" }`
   on its target, that workflow is dispatched once on `main` and watched once
   (`gh run watch --interval 60 --exit-status`; only a dispatch on `main` counts). Railway is
   redeployed and waited for. Key Vault and Secret Manager carry the new fingerprint.
7. **Revoke** the old key by API and probe it until it is refused. With no revoke API (GitHub
   tokens), keys opens the token page, exits 5, and on the next run probes the old token and
   carries on once it is dead.
8. **Record** `fp`, `rotated` and, for a kind that expires, `expires` in the mapping file (only
   those lines of that entry change), clear the item's `previous` field, and print one line per
   target. Commit the mapping file.

```text
$ keys rotate deploy
deploy: 1 preflight: 3 targets reachable
deploy: 2 create: made 'deploy 2026-11-21' fp:775d9721, saved as pending
deploy: 3 probe: the new key fp:775d9721 works (HTTP 200 from api.cloudflare.com/client/v4/user/tokens/verify)
deploy: 4 store: 1Password holds the new key, the old one as previous
deploy: 5 sync: github-actions-env owner/app env:production CLOUDFLARE_API_TOKEN fp:775d9721
...
deploy: 7 revoke: the old key fp:3f9a1c02 is refused now (HTTP 401 from api.cloudflare.com/client/v4/user/tokens/verify)
deploy: 8 record: fp:775d9721, rotated 2026-11-21, expires 2027-05-20
deploy  github-actions-env owner/app env:production CLOUDFLARE_API_TOKEN  fp:775d9721  in use
keys rotate: deploy rotated; commit the mapping file
```

- **Where it stands** is the item's `keys_step` field (with `pending_id`, `previous_id`,
  `unrevoked_id` and `keys_expires`, none of them secret), so a rerun resumes at the step that
  stopped: nothing is minted twice and a finished sync is not repeated. Each save reads the item
  first and saves nothing if another run moved it on meanwhile.
- **A rerun after an unclear answer.** If a probe of the new key gets no clear answer (no
  connection, a 5xx), the key stays in `pending` and a rerun probes it again; only a key the
  provider refuses is revoked. A rerun at step 7 probes the old key first, so an old key whose
  revoke went through but was not recorded counts as gone (a 404 on its delete does too).
- **Rollback.** Until step 7 the old key still works and sits in `previous`. A failure in steps 5
  or 6 writes it back to every target the sync reached, including the one that failed (a write
  that timed out may have landed), redeploys Railway, moves it back to the main field, and
  revokes the new key. If the old key cannot be put back somewhere, 1Password keeps the new key
  and a rerun finishes the rotation instead. If the new key's revoke fails, its id stays in
  `unrevoked_id` and the next run revokes it first. Workflows are dispatched last, after every
  other target checks out; if a rollback follows one, keys names it so it can be run again. A
  failure in step 7 keeps `previous`: the new key is live everywhere, so nothing is broken.
  Step 7 first checks that the new key still works (an owner who deleted the wrong token on the
  provider's page is told so). Nothing is rolled back after step 7.
- **The first value.** An item with no key yet (just made by `keys new`) gets one minted or
  pasted, with nothing to put back or revoke; keys refuses this when a target already holds the
  secret, since a rollback could not restore it. An item with a key but no key id (for a kind
  revoked by id) is refused before anything is made.
- `--dry-run` reads no value from 1Password and changes nothing: it lists the targets, checks
  the Environments and that the items are in their vaults, and prints the plan. Listing a
  Railway target reads its variables (Railway lists names with values), in memory only.
- `--now` is needed for a kind whose provider keeps one key at a time (none of today's kinds),
  since rotating it means a short outage.
- Kinds: `cloudflare-token` (a user token; the new one copies the old one's policies and IP
  condition from `GET /user/tokens/<token_id>`, expires in 180 days, and the old one is deleted;
  the minting token needs Cloudflare's "Create additional tokens" template), `resend-key` (keeps
  the item's `permission`, sending-only unless it says `full_access`, and its `domain_id`;
  minted and deleted with a full-access key; Resend keys have no expiry, so the rotation date
  counts), `github-pat` (the paste flow), and:
  - `twilio-key`: a standard key (not a restricted one: Twilio's key API makes standard keys only, so a restricted key would come back with wider rights), minted and deleted with a Main key (its
    `minted_by` item holds the Main key's `key_sid` and secret) for the item's `account_sid`.
    The new key's SID goes to every target with `field = "key_sid"`. No expiry; the rotation
    date counts.
  - `railway-project-token`: minted with the workspace token named by `minted_by`, for the
    item's `project_id` and `environment_id`, named `<name> <yyyy-mm-dd>` (refused if a token
    of that name is there already), found again by name for its id, and the old one deleted by
    `token_id`. If Railway does not list the new token's id at once, keys records it by its name (unique for the day) and finds it by that name when it is revoked. No expiry.
  - `railway-workspace-token`: only the dashboard makes and deletes one, so keys opens
    `railway.com/account/tokens` for the paste, and again for the old token's delete.
  - `github-app-key`: GitHub makes an App key only as a browser download, on the App's page
    (`owner` is the org that owns the App; leave it out for one your own account owns; the
    item's `slug` names the App). keys opens that page; on the next run it takes the one file
    named `<slug>.<date>.private-key.pem` from `~/Downloads`, saves it in the item's `pending`
    field and deletes the file, so the key is never opened, copied or pasted. Only a file dated on or after the day keys asked counts (an older
    one is an earlier key, maybe the live one), several are refused, an empty one means the
    download is still arriving, and a link is left alone. Since GitHub lists App keys only by
    fingerprint, keys names each the same way (`SHA256:...`) when it asks the owner to delete
    one. A pasted or downloaded value equal to the current key is refused, for every kind. The probe signs a JWT with the key and
    reads `GET /app`. GitHub allows 25 keys at once, so the new key works before the old one
    is deleted on the same page.
  - Railway variables are read back in memory after the sync and their fingerprint compared,
    before each Railway service is redeployed once.
    Account-owned Cloudflare tokens are not handled yet. Not yet proven against the real
    services, only against their API references: Resend's `domain_id`, Cloudflare's
    `result.value`, Twilio's key answer, and Railway's `projectTokenCreate`, `projectTokens` and
    `projectTokenDelete` (undocumented; read from its public GraphQL schema).
- Exit 0 when rotated, 1 when a step failed (the line names it), 3 for a usage error, 5 when it
  waits for the owner (a paste or a click).

### Secrets kept only at their targets: `generated` and `postgres-password`

A secret the app owns (a signing key, a job's key, a datastore password) has no 1Password
item: it lives only at its targets, and `keys rotate` makes the new value itself. The mapping
entry has no `item`; `generate` says the form (`hex32`, the default, or `urlsafe32`, `hex24`
and so on), `redeploy` the order Railway services restart in, and each target may say
`store = "sha256"` (it holds the value's digest) or, on Railway, `previous = "<variable>"`
(where the old value waits during an overlap).

```toml
[[credential]]
name = "jwt-secret"
kind = "generated"
kept_because = "the app signs its sessions with it"

[[credential.target]]
type = "railway"
service = "app"
environment = "production"
variable = "JWT_SECRET"
previous = "JWT_SECRET_FALLBACK"
```

- `keys rotate a b ...` rotates several together: each value is staged without a deploy, each
  Railway service is redeployed once (in `redeploy` order, then the rest), each Railway
  variable is read back and compared by fingerprint, then each GitHub target is set (after the
  app, so a failure strands a job, never a sign-in). Then `fp` and `rotated` are recorded.
- `--keep-previous` (a planned rotation, never after a leak) stages the current value in the
  `previous` variable before the new one, so tokens the old value signed keep working; it
  refuses while an overlap runs. After 30 days, `keys rotate <name> --end-overlap` deletes the
  `previous` variable and redeploys (either way, so a rerun finishes a redeploy that failed).
  A plain rotation deletes any `previous` value, ending the overlap at once, but only once
  every new value is staged (a delete can deploy). With `--keep-previous`, the credentials
  that keep an old value are staged last, and the flag is refused when none does.
- Each service in `redeploy` is looked up before anything changes, so a misspelt one changes
  nothing. A `postgres-password` must list `redeploy` (the app must restart after Redis, say)
  and cannot keep a `previous` value (a database has one password).
- `postgres-password` first changes the database's password over the old URL (the variable
  `url_variable` names), sending a SCRAM verifier so the server never sees the password, then
  stages it, and the new URL must connect before anything restarts. psql gets the password in
  `PGPASSWORD` and its `\set` lines on stdin, never on its command line, and runs with `-X`
  (no `~/.psqlrc`). If anything fails, or the run is interrupted, between the change and
  Railway holding the new password, keys says how to set the database back to what Railway
  holds (the project, service, variable and database user, from inside the container). A URL
  keys cannot split without leaving part of the password on psql's command line is refused.
- A failure or an interruption names what may be staged, counting a write that failed but may
  have landed: rerun (fresh values) after a plain rotation, or after `--keep-previous` when no
  old value was kept yet; once one was, redeploy by hand and end the overlap 30 days after
  that redeploy succeeds; if only GitHub targets were left, they still hold the old value,
  which verifies until the overlap ends.
- `keys sync`, `keys fp` and the 1Password pass of `keys scan` skip these (there is no item);
  `keys check --deep` compares Railway with the mapping file's `fp`, and a digest target only
  for being there.

## Shim for check_key.py

The old key checker, `check_key.py`, becomes a thin shim that runs `keys`. Its
arguments map one to one:

| check_key.py                         | keys                                            |
| ------------------------------------ | ----------------------------------------------- |
| `providers`                          | `keys check --list`                             |
| `fingerprint --key <source>`         | `keys fp --key <source> --hint`                 |
| `leaks <report.json>`                | `keys leaks <report.json>`                      |
| `<service> --key <source> [options]` | `keys check <service> --key <source> [options]` |

Sources `op://`, `kv://`, `env:`, `stdin` and `gitleaks:` carry over. Not carried over, on
purpose: `file:PATH` (keys never reads a key from a file the caller names, since a key file is
itself a copy to leak) and `prompt` (a hidden prompt is typed into a terminal an agent may be
reading; paste the key into 1Password instead and use `op://`). The shim should refuse both with that
advice. What else differs:

- **The fingerprint secret.** keys needs it (`--fp-key` or `$KEYS_FP_KEY`). The shim
  sets `KEYS_FP_KEY` to its 1Password reference (`op://…`) when the caller has not set it, so
  existing calls keep working.
- **Keyed fingerprints.** `fp:` is keyed, so it will not match the unkeyed SHA-256 fingerprints
  check_key.py printed in old issues, nor a `gitleaks:` fingerprint taken from one.
- **`leaks` exits 1 when the report holds any leak** (check_key.py exited 0), and ends with a
  summary line, `keys leaks: N leaked values in M findings`. A finding gitleaks made outside git
  says `not in git` in place of the commit and dates.
- **No length.** check_key.py's `(N chars)` is no longer printed.
- **Key Vault values are read exactly** (as JSON), so a value's own trailing newline is kept;
  check_key.py dropped it.

## The daily scan

`launchd/com.kilotronic.keys-scan.plist` runs `keys scan --patterns-only` every day at 09:15.
launchd reads no shell profile and expands no variables, so the plist names `keys` by its full
path and sets `PATH` and `KEYS_MAPPING` itself; `OWNER` and `MAPPING` are placeholders. Its log,
`~/Library/Logs/keys/scan.log`, holds only what the scan prints: file names, line numbers, rule
or credential names and counts. To install it (by hand; nothing in keys installs it), with the
mapping file's path relative to your home folder:

```sh
mkdir -p ~/Library/Logs/keys ~/Library/LaunchAgents && chmod 700 ~/Library/Logs/keys
sed -e "s|/Users/OWNER|$HOME|g" -e "s|$HOME/MAPPING|$HOME/path/to/keys.toml|" \
  launchd/com.kilotronic.keys-scan.plist > ~/Library/LaunchAgents/com.kilotronic.keys-scan.plist
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.kilotronic.keys-scan.plist
launchctl kickstart gui/$(id -u)/com.kilotronic.keys-scan   # one run now, to see it work
```

The plist expects `keys` in `~/.local/bin` (where `uv tool install` puts it); change the first
`ProgramArguments` string if it is elsewhere. To remove it:
`launchctl bootout gui/$(id -u)/com.kilotronic.keys-scan`, then delete the file from
`~/Library/LaunchAgents`.

By default the scheduled scan looks for secret shapes only, so it never asks for Touch ID with
nobody there. The known-value pass, which reads every credential from 1Password, is opt-in:
delete the `--patterns-only` line, and 1Password asks for Touch ID at 09:15 (with no answer, the
scan exits 2 and names the values it could not search for). If the Mac is asleep at 09:15,
launchd runs the scan when it wakes (missed days count as one run); if it is off, that day's run
is skipped.

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

### `keys install-key`, `keys gh` and `keys git-credential`

Agents sign in to GitHub as an App instead of the owner's own login (design: the auditor's
`practices/key-rotation.md` § _Agents sign in as an App_).

- `keys install-key <name>` copies a `github-app-key` credential's private key and client id from
  1Password into one login-keychain item (`keys:<name>`), through `security -i` on stdin, so
  minting never asks for Touch ID. Off a Mac (Linux has no login keychain) it writes them instead
  to `~/.config/keys/app-keys/<name>.json` (`$XDG_CONFIG_HOME` if set): the folder `0700`, the file
  `0600`, written under a temporary name and renamed into place; `keys gh` refuses a key file
  anyone else can read. It then signs in as the App once to prove the key.
- `keys send-key <name> <host>... [--mapping PATH]` is for Linux machines with no 1Password of
  their own. It reads the key and client id from 1Password on this machine (in memory), signs in
  as the App once to prove them, and writes them into each host's key file over ssh, on stdin:
  never in an argument, never in a local file. On the host the file is written as `install-key`
  writes it (folder `0700`, file `0600`, renamed into place). A host is a name, an ssh_config
  alias or `user@host`; anything else is refused. One failed host doesn't stop the rest; the
  exit code is 1 if any failed.
- `keys gh [--app NAME] -- <gh args>` mints a one-hour installation token for the call's owner
  (from `-R`, `--repo=`, `$GH_REPO`, a github.com URL, a `gh api` path, `--owner` (as
  `gh project` takes it; the token then covers the whole installation), `$KEYS_GH_OWNER` (for a
  call that names no owner, such as `gh project item-edit`: set it once for a script), the current
  repo's `origin`, else `$KEYS_GH_DEFAULT_OWNER`). When the call names a repo or runs in one, the
  token covers only that repo. A GraphQL call (`gh api graphql`) and any `gh project` call take
  only the owner from those sources and get the whole installation: GraphQL names objects by node
  id, which can sit in any of the owner's repos (linking an issue in one repo as a sub-issue of an
  issue in another), and a board holds issues from any repo, so no one repo can bound them. It
  runs the real `gh` with the token as `GH_TOKEN` in gh's environment only (dropping
  `GITHUB_TOKEN` and `GITHUB_PERSONAL_ACCESS_TOKEN`), and revokes it when gh ends. `gh auth token|login|refresh|switch` are refused. The real `gh` is
  `$KEYS_REAL_GH`, else the first `gh` on `PATH` that is not a shim calling `keys gh`.
- `keys git-credential [--app NAME] get` answers git's credential protocol for
  `https://github.com` with `credential.useHttpPath` on, picking the path's owner; it refuses a
  terminal, and leaves other hosts to the next helper.
- An owner with no installation fails with a message naming it: nothing falls back to the
  owner's sign-in. The App is named by `--app`, else the repo owner's entry in
  `$KEYS_GH_APPS` (`owner=app` pairs, split by commas or spaces, e.g.
  `acme-corp=acme-agents jasonluther=kilotronic-agents`); an owner the map doesn't name is
  refused. `--app` is the owner's own override.

## What is next

Phase 2, from the design:

- An issue from day 120 in the nightly check (the workflow lives in the mapping repo).
- The gitleaks pass in `keys scan`, with the shared secret-scan rules and `--redact`, and a
  scan of only the files changed since the last run, for speed.
- The design's other starting kinds: `openai-key` and `azure-app-secret`.
- A check, once, that `op item create` keeps the empty non-secret fields `keys new` asks for
  (`op item create --dry-run` previews without saving).
