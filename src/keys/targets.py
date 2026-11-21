"""The places a credential is delivered to, one adapter per mapping target type.

A value reaches a target only on its CLI's stdin (`gh secret set`, `railway variable set
--stdin`, `az keyvault secret set --file /dev/stdin`, `gcloud secrets versions add
--data-file=-`), never its argv, a file or the terminal. Listing a scope uses metadata only:
names, dates and keys's fingerprint tag. Railway has no metadata-only listing, so its listing is
parsed in process and only the names are kept.

Every target field goes on a child's argv, so each must be a plain name: a value pasted into the
wrong field of the mapping file is refused, and never printed back.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, cast

from keys import mapping, proc
from keys.context import UsageError
from keys.secret import Secret

FP_TAG = "keys-fp"  # the Key Vault tag and Secret Manager label holding the keyed fingerprint

# Each CLI sees only the basics of keys's environment and its own settings.
PREFIXES: dict[str, tuple[str, ...]] = {
    "gh": ("GH_", "GITHUB_"),
    "railway": ("RAILWAY_",),
    "az": ("AZURE_",),
    "gcloud": ("CLOUDSDK_", "GOOGLE_"),
}

_PLAIN = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}"
FIELD_RULES: dict[str, re.Pattern[str]] = {
    "repo": re.compile(rf"{_PLAIN}/{_PLAIN}"),
    "org": re.compile(_PLAIN),
    "repos": re.compile(_PLAIN),
    "environment": re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}"),
    "secret": re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,254}"),
    "variable": re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,254}"),
    "service": re.compile(_PLAIN),
    "project": re.compile(_PLAIN),
    "vault": re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{1,62}"),
}
# Fields shown in output. A Railway project is often a UUID, which is shaped like a Railway
# token, so it is checked but never printed.
NOT_SHOWN = {"project"}
_RUN = re.compile(r"[^\s/]{24,}")

IN_PROGRESS = {"INITIALIZING", "QUEUED", "WAITING", "BUILDING", "DEPLOYING"}
SUCCEEDED = {"SUCCESS", "SLEEPING"}  # a sleeping deployment succeeded and then idled
DEPLOY_ATTEMPTS = 90
DEPLOY_WAIT_S = 10


class TargetError(Exception):
    """A target's CLI failed; names the program, the step and the exit code only."""


@dataclass(frozen=True)
class Present:
    """One secret at a target's scope, as its metadata shows it. Never a value."""

    name: str
    updated_at: str = ""  # ISO 8601 when the store says
    fp: str = ""  # the keyed fingerprint tag or label keys wrote, when there is one


def looks_shaped(text: str) -> bool:
    """A long run of letters and digits together, as keys are."""
    return any(
        any(ch.isalpha() for ch in run) and any(ch.isdigit() for ch in run)
        for run in _RUN.findall(text)
    )


def check_fields(where: str, t: mapping.Target) -> None:
    """Every field of t is a plain name. Raises naming the field, never its content."""
    for key, value in t.fields.items():
        rule = FIELD_RULES.get(key)
        items = value if isinstance(value, list) else [value]
        for item in items:
            ok = rule is not None and rule.fullmatch(item) is not None
            if not ok or (key not in NOT_SHOWN and looks_shaped(item)):
                raise UsageError(f"{where}.{key}: not a plain name keys will pass to a program")


class Adapter:
    """One target: its scope, the secret's name there, and the calls that reach it."""

    program = ""

    def __init__(self, t: mapping.Target, environ: Mapping[str, str], where: str) -> None:
        check_fields(where, t)
        self.target = t
        self.environ = environ
        self.where = where

    def f(self, key: str) -> str:
        value = self.target.fields.get(key, "")
        return value if isinstance(value, str) else ",".join(value)

    @property
    def name(self) -> str:
        """The secret's name at the target."""
        return self.f("variable") or self.f("secret")

    def scope(self) -> tuple[str, ...]:
        """What one listing covers; targets with the same scope share it."""
        raise NotImplementedError

    def describe(self) -> str:
        """type, scope and name, for printing (plain names only, never a Railway project)."""
        raise NotImplementedError

    def write(self, value: Secret, fp: str) -> None:
        raise NotImplementedError

    def listing(self) -> dict[str, Present]:
        """Every secret at this target's scope, by name."""
        raise NotImplementedError

    def _run(self, what: str, argv: list[str], stdin: Secret | None = None) -> str:
        env = proc.child_env(self.environ, PREFIXES.get(argv[0], ()))
        try:
            done = proc.run(argv, env, stdin=stdin)
        except proc.ChildError as e:
            raise TargetError(str(e)) from None
        if done.code != 0:
            raise TargetError(f"{argv[0]} exited {done.code} {what}")
        return done.stdout

    def _json(self, what: str, out: str) -> Any:
        try:
            return json.loads(out or "null")
        except ValueError:
            raise TargetError(f"{self.program} printed something keys cannot read {what}") from None


class _GitHub(Adapter):
    program = "gh"

    def _scope_flags(self) -> list[str]:
        raise NotImplementedError

    def listing(self) -> dict[str, Present]:
        argv = ["gh", "secret", "list", *self._scope_flags(), "--json", "name,updatedAt"]
        rows = self._json("listing secrets", self._run("listing secrets", argv))
        out: dict[str, Present] = {}
        for row in cast(list[Any], rows if isinstance(rows, list) else []):
            if isinstance(row, dict):
                r = cast(dict[str, Any], row)
                out[str(r.get("name", ""))] = Present(
                    str(r.get("name", "")), str(r.get("updatedAt") or "")
                )
        return out


class GitHubRepo(_GitHub):
    def _scope_flags(self) -> list[str]:
        return ["--repo", self.f("repo")]

    def scope(self) -> tuple[str, ...]:
        return ("github-actions", self.f("repo"))

    def describe(self) -> str:
        return f"github-actions {self.f('repo')} {self.name}"

    def write(self, value: Secret, fp: str) -> None:
        argv = ["gh", "secret", "set", self.name, *self._scope_flags()]
        self._run("setting the secret", argv, value)


class GitHubEnv(_GitHub):
    def _scope_flags(self) -> list[str]:
        return ["--repo", self.f("repo"), "--env", self.f("environment")]

    def scope(self) -> tuple[str, ...]:
        return ("github-actions-env", self.f("repo"), self.f("environment"))

    def describe(self) -> str:
        return f"github-actions-env {self.f('repo')} env:{self.f('environment')} {self.name}"

    def write(self, value: Secret, fp: str) -> None:
        argv = ["gh", "secret", "set", self.name, *self._scope_flags()]
        self._run("setting the secret", argv, value)


class GitHubOrg(_GitHub):
    def _scope_flags(self) -> list[str]:
        return ["--org", self.f("org")]

    def scope(self) -> tuple[str, ...]:
        return ("github-actions-org", self.f("org"))

    def describe(self) -> str:
        return f"github-actions-org {self.f('org')} {self.name}"

    def write(self, value: Secret, fp: str) -> None:
        repos = self.f("repos")
        visibility = (
            ["--visibility", "selected", "--repos", repos]
            if repos
            else [
                "--visibility",
                "private",
            ]
        )
        argv = ["gh", "secret", "set", self.name, *self._scope_flags(), *visibility]
        self._run("setting the secret", argv, value)


class Railway(Adapter):
    program = "railway"

    def _scope_flags(self) -> list[str]:
        flags = ["--service", self.f("service"), "--environment", self.f("environment")]
        return flags + (["--project", self.f("project")] if self.f("project") else [])

    def scope(self) -> tuple[str, ...]:
        return ("railway", self.f("project"), self.f("service"), self.f("environment"))

    def service_label(self) -> str:
        return f"{self.f('service')} ({self.f('environment')})"

    def describe(self) -> str:
        return f"railway {self.f('service')}/{self.f('environment')} {self.name}"

    def write(self, value: Secret, fp: str) -> None:
        argv = ["railway", "variable", "set", self.name, "--stdin", "--skip-deploys"]
        self._run("setting the variable", argv + self._scope_flags(), value)

    def listing(self) -> dict[str, Present]:
        # Railway lists values with names; the parsed values are dropped at once.
        argv = ["railway", "variable", "list", *self._scope_flags(), "--json"]
        rows = self._json("listing variables", self._run("listing variables", argv))
        names = list(cast(dict[str, Any], rows)) if isinstance(rows, dict) else []
        del rows
        return {n: Present(n) for n in names}

    def _latest(self) -> tuple[str, str]:
        argv = ["railway", "deployment", "list", *self._scope_flags(), "--json"]
        rows = self._json("listing deployments", self._run("listing deployments", argv))
        try:
            latest = cast(dict[str, Any], cast(list[Any], rows)[0])
            return str(latest["id"]), str(latest["status"])
        except (LookupError, TypeError):
            raise TargetError(f"{self.service_label()} has no readable deployment list") from None

    def redeploy(self, sleep: Callable[[float], None] = time.sleep) -> None:
        """Redeploy and wait for the new deployment to succeed, told from the old by its id."""
        previous, status = self._latest()
        for _ in range(DEPLOY_ATTEMPTS):  # Railway refuses to redeploy one still in flight
            if status not in IN_PROGRESS:
                break
            sleep(DEPLOY_WAIT_S)
            previous, status = self._latest()
        else:
            raise TargetError(f"{self.service_label()}: the last deployment never finished")
        self._run("redeploying", ["railway", "redeploy", *self._scope_flags(), "--yes"])
        for _ in range(DEPLOY_ATTEMPTS):
            ident, status = self._latest()
            if ident != previous and status not in IN_PROGRESS:
                if status not in SUCCEEDED:
                    shown = status if re.fullmatch(r"[A-Z_]{1,20}", status) else "unknown"
                    raise TargetError(f"{self.service_label()}: the deployment ended {shown}")
                return
            sleep(DEPLOY_WAIT_S)
        raise TargetError(f"{self.service_label()}: the deployment did not finish")


class AzureKeyVault(Adapter):
    program = "az"

    def scope(self) -> tuple[str, ...]:
        return ("azure-key-vault", self.f("vault"))

    def describe(self) -> str:
        return f"azure-key-vault {self.f('vault')} {self.name}"

    def write(self, value: Secret, fp: str) -> None:
        argv = ["az", "keyvault", "secret", "set", "--vault-name", self.f("vault")]
        argv += ["--name", self.name, "--file", "/dev/stdin", "--tags", f"{FP_TAG}={fp}"]
        argv += ["--output", "none"]
        self._run("setting the secret", argv, value)

    def listing(self) -> dict[str, Present]:
        argv = ["az", "keyvault", "secret", "list", "--vault-name", self.f("vault")]
        rows = self._json("listing secrets", self._run("listing secrets", [*argv, "-o", "json"]))
        out: dict[str, Present] = {}
        for row in cast(list[Any], rows if isinstance(rows, list) else []):
            if not isinstance(row, dict):
                continue
            r = cast(dict[str, Any], row)
            name = str(r.get("name") or str(r.get("id", "")).rsplit("/", 1)[-1])
            tags = cast(dict[str, Any], r.get("tags") or {})
            attrs = cast(dict[str, Any], r.get("attributes") or {})
            out[name] = Present(name, str(attrs.get("updated") or ""), _fp(tags.get(FP_TAG)))
        return out


class GcpSecret(Adapter):
    program = "gcloud"

    def scope(self) -> tuple[str, ...]:
        return ("gcp-secret", self.f("project"))

    def describe(self) -> str:
        return f"gcp-secret {self.f('project')} {self.name}"

    def write(self, value: Secret, fp: str) -> None:
        project = ["--project", self.f("project")]
        label = f"{FP_TAG}={fp}"
        if self.name not in self.listing():
            argv = ["gcloud", "secrets", "create", self.name, *project]
            argv += ["--replication-policy", "automatic", "--data-file=-", "--labels", label]
            self._run("creating the secret", argv, value)
            return
        argv = ["gcloud", "secrets", "versions", "add", self.name, *project, "--data-file=-"]
        self._run("adding a version", argv, value)
        argv = ["gcloud", "secrets", "update", self.name, *project, "--update-labels", label]
        self._run("labelling the secret", argv)

    def listing(self) -> dict[str, Present]:
        argv = ["gcloud", "secrets", "list", "--project", self.f("project"), "--format", "json"]
        rows = self._json("listing secrets", self._run("listing secrets", argv))
        out: dict[str, Present] = {}
        for row in cast(list[Any], rows if isinstance(rows, list) else []):
            if not isinstance(row, dict):
                continue
            r = cast(dict[str, Any], row)
            name = str(r.get("name", "")).rsplit("/", 1)[-1]
            labels = cast(dict[str, Any], r.get("labels") or {})
            out[name] = Present(name, str(r.get("createTime") or ""), _fp(labels.get(FP_TAG)))
        return out


def _fp(value: object) -> str:
    return value if isinstance(value, str) and mapping.FP.fullmatch(value) else ""


ADAPTERS: dict[str, type[Adapter]] = {
    "github-actions": GitHubRepo,
    "github-actions-env": GitHubEnv,
    "github-actions-org": GitHubOrg,
    "railway": Railway,
    "azure-key-vault": AzureKeyVault,
    "gcp-secret": GcpSecret,
}


def adapter(t: mapping.Target, environ: Mapping[str, str], where: str) -> Adapter:
    """The adapter for t. `where` names it in errors (`credential[0] (app).target[1]`)."""
    return ADAPTERS[t.type](t, environ, where)


def adapters(c: mapping.Credential, environ: Mapping[str, str]) -> list[Adapter]:
    """An adapter for each of c's targets, every field checked before any is used."""
    return [adapter(t, environ, f"{c.name}.target[{i}]") for i, t in enumerate(c.targets)]
