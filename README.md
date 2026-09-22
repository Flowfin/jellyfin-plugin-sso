<!-- markdownlint-disable MD041 -->

<h1 align="center">Community SSO for Jellyfin</h1>

<p align="center">
<img alt="Community SSO for Jellyfin" src="https://raw.githubusercontent.com/Flowfin/jellyfin-plugin-sso/main/img/banner.png" width="820"/>
<br/>
<br/>
<a href="https://github.com/Flowfin/jellyfin-plugin-sso/blob/main/LICENSE.txt">
<img alt="GPL 3.0 License" src="https://img.shields.io/github/license/Flowfin/jellyfin-plugin-sso.svg"/>
</a>
<a href="https://github.com/Flowfin/jellyfin-plugin-sso/releases">
<img alt="Last release for Jellyfin 10.11" src="https://img.shields.io/github/v/release/Flowfin/jellyfin-plugin-sso?display_name=tag&filter=4.*&label=last%20release%20(Jellyfin%2010.11)"/>
</a>
<a href="https://github.com/Flowfin/jellyfin-plugin-sso/releases">
<img alt="Stable release for Jellyfin 12" src="https://img.shields.io/github/v/release/Flowfin/jellyfin-plugin-sso?display_name=tag&filter=5.*&label=stable%20(Jellyfin%2012)"/>
</a>
<a href="https://github.com/Flowfin/jellyfin-plugin-sso/releases">
<img alt="Beta release for Jellyfin 12" src="https://img.shields.io/github/v/release/Flowfin/jellyfin-plugin-sso?display_name=tag&include_prereleases&filter=5.*-JF12-beta.*&label=beta%20(Jellyfin%2012)"/>
</a>
<a href="https://github.com/Flowfin/jellyfin-plugin-sso/actions/workflows/dotnet.yml">
<img alt="Build Status" src="https://github.com/Flowfin/jellyfin-plugin-sso/actions/workflows/dotnet.yml/badge.svg"/>
</a>
<a href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki">
<img alt="Documentation" src="https://img.shields.io/badge/docs-wiki-blue"/>
</a>
<a href="https://www.bestpractices.dev/projects/13660">
<img alt="OpenSSF Best Practices" src="https://www.bestpractices.dev/projects/13660/badge"/>
</a>
<a href="https://securityscorecards.dev/viewer/?uri=github.com/Flowfin/jellyfin-plugin-sso">
<img alt="OpenSSF Scorecard" src="https://api.securityscorecards.dev/projects/github.com/Flowfin/jellyfin-plugin-sso/badge"/>
</a>
</p>

<p align="center">
Sign in to Jellyfin with your existing identity provider - Keycloak, Authelia, authentik, Entra ID, Google, and more - over <b>OpenID&nbsp;Connect</b> or <b>SAML&nbsp;2.0</b>, instead of a separate Jellyfin password.
</p>

> ### 🔁 Revival
>
> A security-first continuation of [**9p4/jellyfin-plugin-sso**](https://github.com/9p4/jellyfin-plugin-sso), archived by its author, carried on from **4.0.0.x**. **5.x** is the line for Jellyfin 12 (.NET 10); **4.3.1** is the last build for Jellyfin 10.11 (.NET 9) and the line is frozen. One repository URL serves both, and your server installs the build that runs on it. Thanks to the original author and contributors for the foundation.
>
> ### 🤝 AI-assisted, human-owned
>
> Claude (Anthropic) works here like a trainee: useful when it works, and just as capable of nonsense as any junior developer. It drafts code, runs the adversarial security reviews, and translates documentation and comments into English. Nothing it produces ships unread - I review, edit and sign off every line, and the responsibility is mine.

## Features

- **OpenID Connect and SAML 2.0** - either or both, multiple providers side by side.
- **Role-based access control** - map identity-provider groups/roles to login, administrator, library folders, Live TV, generic permissions, and a per-group parental-rating ceiling.
- **Hardened, fail-closed login path** - identities bound to the stable `sub` / `NameID`, fail-closed SAML and `id_token` validation, and SSRF-guarded avatar fetches.
- **Optional SSO-only login** - disable password login for every account except a designated break-glass admin, behind a fail-closed last-admin guard.
- **Avatar sync, Quick Connect, and self-service account linking.** Which client reaches SSO by which mechanism, and what has actually been exercised: [Client Compatibility](https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Client-Compatibility).
- **Tested** - a growing xUnit suite over the security-critical paths, with CI (build, format, CodeQL) on every change.

How this plugin compares to Jellyfin's built-in auth, the official LDAP plugin, and the archived 9p4 plugin: see the [Comparison](https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Comparison) wiki page.

## Supported providers

Any OIDC-conformant or SAML 2.0 identity provider should work. Keycloak, Authelia, authentik, Dex, Pocket ID, Kanidm, Zitadel, and Google have verified, step-by-step guides - with the per-provider caveats - on the [Provider Setup](https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Provider-Setup) wiki page.

The self-hostable providers run in an automated end-to-end login test in CI ([`e2e-login.yml`](.github/workflows/e2e-login.yml)); cloud providers (Google, Entra ID) can't run in ephemeral CI and are verified manually. A verified guide (or a test) for a provider you use is a welcome contribution.

## Installing

> **This is an independent plugin repository** - it is not in Jellyfin's built-in catalog. You install it by adding **its** repository under **Plugins → Repositories**.

1. In Jellyfin, go to **Dashboard → Plugins → Repositories** and add the repository URL of the channel you want. Each URL serves both generations: a Jellyfin 12 server installs the current 5.x build, a 10.11 server the last one made for it, 4.3.1.

   **Stable** - releases promoted after their soak; the channel for a server with real accounts:

   ```
   https://raw.githubusercontent.com/Flowfin/jellyfin-plugin-sso/manifest-release/manifest.json
   ```

   **Beta** - every build as it lands, ahead of the stable; for testing and for reporting back:

   ```
   https://raw.githubusercontent.com/Flowfin/jellyfin-plugin-sso/manifest-beta/manifest.json
   ```

2. Go to **Dashboard → Plugins → Catalog**, find **Community SSO for Jellyfin**, and install it.
3. **Restart Jellyfin.**

It installs over the original `9p4` plugin in place and keeps your configuration. Building from source, the channels, migrating from the old manifest and which clients can sign in are on the wiki: [Installation](https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Installation) and [Client Compatibility](https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Client-Compatibility).

## Configuration

Configure your providers on the plugin's settings page (**Dashboard → Plugins → SSO-Auth**) and via the admin API. The [Provider Setup](https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Provider-Setup) walkthrough and the [Hardening & Options Reference](https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Hardening-and-Options-Reference) cover every option, the provider-name rules, and the admin-API details. Deployments that keep their configuration in version control can declare providers in a mounted file or in environment variables instead: [Config as code](https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Config-as-code) covers the document, the variable naming scheme, what wins between the sources, and how a secret is referenced rather than written into the file.

## Documentation

Full documentation lives in the **[Wiki](https://github.com/Flowfin/jellyfin-plugin-sso/wiki)**:

- [Installation](https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Installation) · [Provider Setup](https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Provider-Setup) · [Login Flow](https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Login-Flow) · [Client Compatibility](https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Client-Compatibility) · [Security Model](https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Security-Model) · [Troubleshooting](https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Troubleshooting)
- Building a provisioning tool (Wizarr, jfa-go, a request manager)? The [Account-management API](docs/ACCOUNT-MANAGEMENT-API.md) page covers creating an account that is SSO-linked before its first login.
- Rebuilding or moving a server? [Server migration and rebuild](docs/SERVER-MIGRATION.md) covers the two backup files, the order they have to be restored in, and what is deliberately never restored.
- Monitoring the sign-in path? [Metrics](https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Metrics) covers the counters the plugin publishes, the administrator token the endpoint asks for, and a scrape config to paste.
- Project policies: [Governance](GOVERNANCE.md) · [Support & security updates](SECURITY.md#supported-versions--security-updates) · [Remediation & secrets policy](docs/SECURITY-REMEDIATION-POLICY.md)

The plugin's own served pages are translatable from JSON catalogs, no C# involved. [Translating the UI](CONTRIBUTING.md#translating-the-ui) lists the supported languages, the catalog format, and how to add one.

Setup questions ("how do I configure provider X") go to [Discussions Q&A](https://github.com/Flowfin/jellyfin-plugin-sso/discussions/categories/q-a), defects to the [issue tracker](https://github.com/Flowfin/jellyfin-plugin-sso/issues), and vulnerabilities to a [private advisory](https://github.com/Flowfin/jellyfin-plugin-sso/security/advisories/new) rather than either public channel.

## Security

This plugin is built to **fail closed by default**: a missing signature, a weak signature or under-strength key, an out-of-bounds time window, a wrong audience, a replayed assertion, or an unrecognized identity is rejected rather than waved through. Secrets are stored write-only and AES-256-GCM-encrypted at rest. The controls and their tuning - encryption at rest, optional rate limiting, new-user approval, step-up/MFA passthrough - are on the [Security Model](https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Security-Model) wiki page, and security-relevant behavior is covered by the test suite.

Found a vulnerability? Please report it **privately** via GitHub's ["Report a vulnerability"](https://github.com/Flowfin/jellyfin-plugin-sso/security/advisories/new) - not the public issue tracker. See [SECURITY.md](SECURITY.md).

## Contributing

Issues and pull requests are welcome. The plugin targets **.NET 9 / Jellyfin 10.11** and **.NET 10 / Jellyfin 12**. Build with `dotnet build` / `dotnet publish` and run the tests with `dotnet test` (the runner needs the .NET 10 SDK). CI builds and tests every change, and the login path goes through an adversarial review. See [CONTRIBUTING.md](CONTRIBUTING.md) for the workflow.

## Credits

Built on the [Jellyfin LDAP plugin](https://github.com/jellyfin/jellyfin-plugin-ldapauth), [AspNetSaml](https://github.com/jitbit/AspNetSaml/) (SAML), and the [Duende IdentityModel OIDC Client](https://github.com/DuendeSoftware/foss) (OpenID Connect) - and on the original [9p4/jellyfin-plugin-sso](https://github.com/9p4/jellyfin-plugin-sso) and its contributors.

## License

Licensed under the [GNU GPL v3.0](https://github.com/Flowfin/jellyfin-plugin-sso/blob/main/LICENSE.txt).

See NOTICE.md for the intended-use notice.
