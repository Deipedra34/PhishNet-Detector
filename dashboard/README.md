# PhishNet Web Dashboard

A browser UI for [PhishNet Detector](../README.md), built with React and
[Vite](https://vitejs.dev/). It talks to the REST API that `phishnet serve` runs, and
`phishnet serve` can host the built dashboard on the same port.

| Page | What it does | API it uses |
|------|--------------|-------------|
| **Scan** (`/`) | Scan a URL, or an email (upload an `.eml` file or paste the raw source), and see the risk score, level, matched signals, domain age, threat feed matches, and ML confidence (when the result includes it) | `POST /api/scan/url`, `POST /api/scan/email` |
| **History** (`/history`) | Past scans from the CLI and the API, newest first, with search, risk/type filters, and pagination | `GET /api/history` |
| **Stats** (`/stats`) | Totals, scans per risk level, and the most frequently flagged domains, the same figures as `phishnet history stats` | `GET /api/history/stats` |
| **Feeds** (`/feeds`) | OpenPhish/PhishTank cache freshness and entry counts, as `phishnet feeds status` reports them | `GET /api/feeds/status` |

## Requirements

- Node.js 18.18 or newer, with npm
- A running PhishNet API (`phishnet serve`, Java 26). See the main README.

## Development

Run the API and the Vite dev server side by side. The dev server reloads the page as
you edit, and forwards every `/api/...` request to the API, so the browser only ever
talks to one origin.

```bash
# Terminal 1: the API, from the repository root
mvn -B package
java -jar target/phishnet.jar serve            # http://localhost:8080

# Terminal 2: the dashboard
cd dashboard
npm install
npm run dev                                    # http://localhost:5173
```

The proxy target defaults to `http://localhost:8080`. To use an API on another
address, set `PHISHNET_API_URL` when you start the dev server:

```bash
PHISHNET_API_URL=http://localhost:9090 npm run dev
```

## Production build

```bash
cd dashboard
npm install
npm run build          # writes static files to dashboard/dist/
```

`dashboard/dist/` is plain HTML, CSS, and JavaScript, with no server-side code. The
API server serves it:

```bash
# From the repository root: dashboard/dist is found automatically
java -jar target/phishnet.jar serve
#   ...
#   Web dashboard: http://localhost:8080/ (from .../dashboard/dist)

# Or point at it explicitly, from anywhere
java -jar target/phishnet.jar serve --dashboard /path/to/dashboard/dist
```

When `--dashboard` isn't given, `phishnet serve` uses the first of these that contains
an `index.html`:

1. the directory in the `PHISHNET_DASHBOARD_DIR` environment variable (the Docker image sets this)
2. `dashboard/dist` under the current directory (a source checkout)
3. a `dashboard/` folder next to `phishnet.jar`

If none exists, the server runs the API only, as before, and says so at startup.
`--no-dashboard` turns the dashboard off even when it has been built.

The built pages call the API with relative paths (`/api/...`), so the dashboard and the
API always share an origin and need no CORS setup. Reloading a page such as
`/history?risk=HIGH` works because the server answers every non-API path that isn't
a file with `index.html`.

`npm run preview` serves `dist/` on its own (port 4173) for a quick check of the
build. It doesn't proxy the API, so use `phishnet serve` to try the real thing.

The [Docker image](../README.md#docker) builds the dashboard in its own stage and
ships it, so `docker run -p 8080:8080 <image> serve` serves the dashboard too.

## The API key

`phishnet serve` 2.9.0 and newer require an API key on every request except
`GET /api/health`. On its first load the dashboard shows an **Enter your API key**
screen: paste the key that `phishnet serve` printed when it first started (it's also
in `~/.phishnet/api-key` on the server). The dashboard checks it with
`GET /api/auth/check` and only saves it, in this browser's local storage, if the
server accepts it. After that every request carries it in the `X-API-Key` header.

- **Forget API key**, in the page footer, removes it from this browser.
- If the server's key is replaced (`phishnet serve --regenerate-key`), the next
  rejected request brings the key screen back.
- Against a server started with `--no-auth`, or one older than 2.9.0, the dashboard
  never asks.

The key screen appears in development mode too: the Vite dev server forwards the
header to the API.

## Languages

The dashboard is in English and Turkish (Türkçe). The language menu at the right of
the header switches it at once; the choice is kept in this browser's local storage
(`phishnet.language`), next to the API address and key. On a first visit the
dashboard follows the browser's preferred languages and falls back to English.

The dashboard's own text - menus, labels, buttons, its own error messages, dates and
numbers - comes from `src/i18n/en.json` and `src/i18n/tr.json`; a key missing from
one falls back to English. Text that comes from the API (scan results, the API's
error messages) is shown as the server sends it: every request carries an
`Accept-Language` header with the dashboard's language, so the server answers in the
same one. A result that's already on screen stays in the language it was scanned in.

To add a language, add `src/i18n/<code>.json` with the same keys and register it in
`src/i18n/index.js` (`DICTIONARIES` and `LANGUAGE_NAMES`). Placeholders look like
`{name}`, and keys with `.one`/`.other` variants are picked by the `count` value.

## Choosing the API address

By default every request goes to the origin the dashboard was loaded from. To use a
different one:

- **At build time:** set `VITE_API_BASE_URL`, e.g. `VITE_API_BASE_URL=/phishnet npm run build`
  for an API behind a reverse proxy under `/phishnet`.
- **At runtime:** click **Change** next to "API" in the page footer. The dashboard checks
  `GET /api/health` at the new address before saving it in this browser's local storage.
  **Use this server** goes back to the default.

The API only grants cross-origin (CORS) access to browser-extension pages, so a
different address must be same-origin from the browser's point of view: a path
prefix, or a host behind the same reverse proxy. A dashboard on one origin can't call
an API on another.

## Tests

```bash
npm test               # one run (Vitest + jsdom)
npm run test:watch     # re-runs on every change
```

The tests cover the API client (`src/api/client.test.js`: URL building, request
shapes, error handling, the API key header and its storage, 401 and 429 handling),
the key screen (`src/components/AuthGate.test.jsx`: when it appears, wrong and right
keys, a key that stops working), the footer settings (`src/components/ApiSettings.test.jsx`),
the scan result card (`src/components/ScanResultCard.test.jsx`:
risk level colors and labels, signals, domain age, feed matches, ML confidence, email
details), the translations (`src/i18n/i18n.test.js`: both files have the same keys and
placeholders, fallbacks, plurals, and how the language is detected and remembered),
and the language switcher (`src/components/LanguageSwitcher.test.jsx`: switching swaps
the page's text, the choice survives a reload, and the API is asked for the chosen
language). The backend endpoints are tested by the Maven build (`DashboardApiTest`).

## Layout

```
dashboard/
├── index.html               entry page
├── vite.config.js           build output, dev proxy, and test setup
├── public/                  copied into dist/ as-is (favicon)
└── src/
    ├── main.jsx, App.jsx    bootstrapping and routes
    ├── index.css            shared dark theme (colors from assets/banner.svg)
    ├── format.js            date, number, and duration formatting
    ├── i18n/                index.js (useI18n, language detection and storage), en.json, tr.json
    ├── api/client.js        fetch-based API client
    ├── components/          Layout, LanguageSwitcher, AuthGate and ApiKeySetup (API key screen), ScanResultCard, RiskBadge, Pagination, ApiSettings
    ├── pages/               ScanPage, HistoryPage, StatsPage, FeedsPage, NotFoundPage
    └── test/setup.js        Vitest setup
```

Dependency versions are pinned exactly in `package.json`.
