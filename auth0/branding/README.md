# Hosted Onesa Account

The production Auth0 Universal Login theme uses the shared Onesa identity palette (deep forest, green, navy and soft mint), the Onesa logo, and rounded cards and fields. The account application uses the same palette and interaction styling. English and German overrides cover the combined and identifier-first sign-in and registration screens. The application name is supplied by Auth0 for each transaction. Credential entry, MFA, recovery, account linking and approval follow their existing flows.

In the production Auth0 tenant language settings, keep English (`en`) as the default and enable German (`de`). Auth0 selects a supported language for each transaction using the requested `ui_locales` or the browser language. The branding sync manages translations for both languages; language enablement and the default remain tenant settings. [Auth0 Universal Login internationalization](https://auth0.com/docs/customize/internationalization-and-localization/universal-login-internationalization)

From the repository root with Node 24, supply a short-lived Onesa management token in the environment through your credential manager. Use audience `https://onesa.eu.auth0.com/api/v2/` with `read:branding` and `read:prompts`; applying changes also requires `update:branding` and `update:prompts`.

```sh
node auth0/branding/sync.js --check
node auth0/branding/sync.js --apply
```

The command reads `AUTH0_MANAGEMENT_TOKEN`. Check mode reports differences with exit code 1. Apply updates the default theme and merges each prompt's owned labels into the existing language overrides, then reads them back. Rerun after an interruption. Coordinate theme and prompt edits with other tenant administrators while applying. Review by entering a protected application and following its sign-up link. Custom text alone does not enable registration on a connection or approve access to a product.
