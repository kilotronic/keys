"""The kinds of credential keys knows: their 1Password fields and how their console shows them."""

from __future__ import annotations

from dataclasses import dataclass

VALUE_FIELD = "credential"  # the concealed field of a 1Password API Credential item


@dataclass(frozen=True)
class Kind:
    name: str
    about: str
    fields: tuple[str, ...] = ()  # the non-secret fields the item also has
    provider_issued: bool = True  # a provider made it, so its console shows a hint
    # The provider can set an expiry on it. When not, the rotation date counts: it expires
    # 180 days after it was rotated.
    can_expire: bool = False
    # The provider keeps one key at a time (a roll in place), so rotating it means a short
    # outage: keys rotate refuses it without --now.
    single_key: bool = False
    # The app owns it and it lives only at its targets (a signing key, a datastore password):
    # no 1Password item; keys rotate makes the new value itself.
    runtime: bool = False


KINDS: dict[str, Kind] = {
    k.name: k
    for k in [
        Kind("github-app-key", "a GitHub App's private key", ("app_id", "client_id", "slug")),
        Kind(
            "github-pat",
            "a GitHub fine-grained personal access token",
            ("owner",),
            can_expire=True,
        ),
        Kind(
            "railway-project-token",
            "a Railway project token",
            ("project_id", "environment_id", "token_id"),
        ),
        Kind("railway-workspace-token", "a Railway workspace or account token"),
        Kind("twilio-key", "a Twilio API key (its secret)", ("key_sid", "account_sid")),
        Kind(
            "cloudflare-token",
            "a Cloudflare API token",
            ("token_id", "account_id"),
            can_expire=True,
        ),
        Kind(
            "resend-key",
            "a Resend API key",
            ("key_id", "domain_id", "permission"),
        ),
        Kind("generic", "any other credential", (), provider_issued=False),
        Kind(
            "generated",
            "a random secret the app owns (a signing key), kept only at its targets",
            provider_issued=False,
            runtime=True,
        ),
        Kind(
            "postgres-password",
            "a Postgres password, changed in the database first, kept only at its targets",
            provider_issued=False,
            runtime=True,
        ),
    ]
}
