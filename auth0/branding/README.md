# Hosted Onesa Account

The production Auth0 Universal Login theme uses the Company Portal logo, colors, card and field shapes. English and German overrides cover the combined and identifier-first sign-in and registration screens. The application name is supplied by Auth0 for each transaction. Credential entry, MFA, recovery, account linking and approval follow their existing flows.

From the repository root with Node 24, supply a short-lived Onesa management token in the environment through your credential manager. Use audience `https://onesa.eu.auth0.com/api/v2/` with `read:branding` and `read:prompts`; applying changes also requires `update:branding` and `update:prompts`.

```sh
node auth0/branding/sync.js --check
node auth0/branding/sync.js --apply
```

The command reads `AUTH0_MANAGEMENT_TOKEN`. Check mode reports differences with exit code 1. Apply updates the default theme and merges each prompt's owned labels into the existing language overrides, then reads them back. Rerun after an interruption. Coordinate theme and prompt edits with other tenant administrators while applying. Review by entering a protected application and following its sign-up link. Custom text alone does not enable registration on a connection or approve access to a product.
