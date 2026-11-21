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


KINDS: dict[str, Kind] = {
    k.name: k
    for k in [
        Kind("github-app-key", "a GitHub App's private key", ("app_id", "client_id")),
        Kind("github-pat", "a GitHub fine-grained personal access token", ("owner",)),
        Kind("railway-project-token", "a Railway project token", ("project_id", "environment")),
        Kind("cloudflare-token", "a Cloudflare API token", ("token_id", "account_id")),
        Kind("generic", "any other credential", (), provider_issued=False),
    ]
}
