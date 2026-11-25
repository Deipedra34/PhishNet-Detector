# PhishNet Detector browser extension

A small Chrome / Edge / Firefox extension (Manifest V3) that checks the page
you're on with your own PhishNet Detector REST API (`phishnet serve`) and shows
the result in a toolbar popup:

- the risk level - **LOW** (green), **MEDIUM** (yellow), or **HIGH** (red) -
  and the 0-100 score
- the recommendation, and the domain age when the server looked it up
- the top signals that drove the score (up to five, with their ids and evidence)

<p>
  <img src="icons/icon-128.png" alt="PhishNet extension icon" width="64">
</p>

It's plain HTML, CSS, and JavaScript with no build step or dependencies, and
it isn't part of the Java build - load the folder into your browser as
described below.

## How it works

1. You click the PhishNet icon in the toolbar.
2. The popup reads the address of the current tab and sends it to
   `POST /api/scan/url` on your PhishNet API (by default `http://localhost:8080`).
3. It shows "Checking…" while it waits, then the result - or a clear error if
   the API can't be reached (e.g. "Can't reach PhishNet API at
   http://localhost:8080 — is "phishnet serve" running?") with a **Try again**
   button.

Pages are **only checked when you click the icon**. The extension has no
background script and doesn't watch your browsing; there's no automatic
checking of every page you visit. Browser-internal pages (`chrome://`,
`about:`, `edge://`), local files, and other extensions' pages can't be checked
and say so.

### Privacy

The only data the extension sends anywhere is the address of the page you
clicked it on, and only to the API address in its settings - your own server.
It stores just its settings - the API address, the API key, and the language - in
the browser's extension storage. Note that
the PhishNet server records each scan in its
[scan history database](../README.md#scan-history) like any other API scan;
start it with `--no-history-db` if you don't want that.

## 1. Start the PhishNet API

From the project root (see the main README's
[REST API section](../README.md#rest-api-serve-mode)):

```bash
mvn clean package
java -jar target/phishnet.jar serve            # http://localhost:8080
```

Or with Docker (see [Docker](../README.md#docker)):

```bash
docker run --rm -p 8080:8080 ghcr.io/deipedra34/phishnet-detector serve --port 8080
```

Either way the API is then at `http://localhost:8080`, which is the
extension's default. Check it with `curl http://localhost:8080/api/health`.

**Copy the API key it prints.** Since version 2.9.0, `phishnet serve` requires
an API key on every scan. The first start generates one and prints it once:

```
Generated a new API key and saved it to /home/you/.phishnet/api-key:

    Zr4nE8vQx1Lk9wTb2yHc7uJm5sPa3dGf6oKi0eNqW-A
```

You'll paste it into the extension's settings in step 3. Missed it? It's in
`~/.phishnet/api-key` on the server (in Docker: `docker logs <container>`, or
`docker exec <container> cat /home/phishnet/.phishnet/api-key`), and
`phishnet serve --regenerate-key` makes a new one.

## 2. Load the extension

The extension isn't published to the browser stores; load it from this folder.

### Chrome, Edge, and other Chromium browsers

1. Open `chrome://extensions` (Edge: `edge://extensions`).
2. Turn on **Developer mode**.
3. Click **Load unpacked** and select this `browser-extension/` folder.
4. Optional: pin PhishNet from the extensions (puzzle-piece) menu so its icon
   stays in the toolbar.

It stays installed across restarts. After pulling changes, click the reload
icon on its card.

### Firefox (128 or newer)

1. Open `about:debugging#/runtime/this-firefox`.
2. Click **Load Temporary Add-on…** and select `browser-extension/manifest.json`.

Firefox removes temporary add-ons when it restarts, so repeat this after each
restart (installing it permanently requires
[signing it through addons.mozilla.org](https://extensionworkshop.com/documentation/publish/signing-and-distribution-overview/)).

## 3. Settings

Right-click the toolbar icon → **Options** (Firefox: **Manage Extension** →
**Preferences**), or use the **Settings** link in the popup.

- **PhishNet API address** - where your `phishnet serve` instance listens.
  Default `http://localhost:8080`. Examples:
  - another port: `http://localhost:9090` (e.g. `phishnet serve --port 9090`,
    or Docker with `-p 9090:8080`)
  - another machine or a container host on your network: `http://192.168.1.20:8080`
  - behind a reverse proxy: `https://phishnet.example.internal` (a path prefix
    such as `https://example.internal/phishnet` works too)
- **API key** - the key `phishnet serve` printed (see step 1). It's sent in
  the `X-API-Key` header with every scan and kept in the browser's extension
  storage. Tick **Show** to check what you pasted. Leave it empty for a server
  started with `--no-auth`.
- **Test connection** checks the address and the key in the boxes, without
  saving them: `GET /api/health` to see the server answers, then
  `GET /api/auth/check` to see it accepts the key. A server older than 2.9.0
  has no API keys, and the test says so.
- **Reset to default** goes back to `http://localhost:8080` (the key is kept).
- **Language** - see [Languages](#languages) below. Takes effect as soon as you pick it.

**Upgrading from an older PhishNet:** after the server is upgraded to 2.9.0
or newer, scans fail with "PhishNet API requires an API key" until you paste
the key here.

When you save an address on a host other than `localhost` / `127.0.0.1`, the
browser asks whether PhishNet may access that host. Allowing it is
recommended but not required - see the next section.

## Languages

The popup and the settings page are in English and Turkish (Türkçe). By default
(**Automatic**) they follow the browser's language, falling back to English; the
**Language** setting picks one regardless of the browser. The extension's name,
description, and toolbar tooltip always follow the browser's language - browsers
read those from the manifest themselves.

The text lives in `_locales/en/messages.json` and `_locales/tr/messages.json` (the
standard extension format). Messages from the API - scan results and its error
messages - come in the same language: every request sends an `Accept-Language`
header with the extension's language, and `phishnet serve` 3.0.0 and newer answer
in it (older servers answer in English).

To add a language, add `_locales/<code>/messages.json` with the same keys and
placeholders, then list the code in `lib/i18n.js` (`LANGUAGES` and
`LANGUAGE_NAMES`) and add it to the picker in `options.html`.

## Permissions and cross-origin requests

| Permission | Why |
| --- | --- |
| `activeTab` | Read the current tab's address, only when you click the icon |
| `storage` | Remember the API address, API key, and language |
| host access to `localhost` and `127.0.0.1` | Call a local `phishnet serve` (any port) |
| optional host access (`http://*/*`, `https://*/*`) | Asked for one host at a time, only when you save an API address on another host |

The popup calls the API from its own extension origin
(`chrome-extension://…` or `moz-extension://…`), which makes it a cross-origin
request. It works either way:

- With host access to the API's host (always the case for `localhost` /
  `127.0.0.1`, or after you allow the prompt for another host), the browser
  lets the extension through on its own. Any `phishnet serve` version works.
- Without it, the PhishNet server must allow the request with CORS headers.
  Since version 2.4.0, `phishnet serve` does so for browser-extension origins
  only - ordinary websites still get no CORS access, so a page you visit
  can't use your local API.

So for an API on another host, either allow the permission prompt or run
PhishNet 2.4.0 or newer (ideally both).

## Chrome vs. Firefox differences

One manifest works in both. The browser-specific bits:

- `browser_specific_settings.gecko` (the add-on ID and minimum Firefox
  version) is Firefox-only. Chrome ignores it but lists an
  *"Unrecognized manifest key 'browser_specific_settings'"* warning on the
  extension's card - that's harmless.
- `optional_host_permissions` needs Firefox 128 or newer, hence the minimum
  version.
- Firefox can show host access to `localhost` as something to allow on the
  extension's **Permissions** tab in `about:addons`. If it isn't allowed, the
  extension still works with PhishNet 2.4.0+ through CORS.
- The code uses the `browser` namespace when it exists (Firefox) and `chrome`
  otherwise (see `lib/api.js`); only APIs both browsers support are used.

## Troubleshooting

| Popup says | What to check |
| --- | --- |
| Can't reach PhishNet API … | Is `phishnet serve` running, and is the address in Settings right? For Docker, is the port published (`-p 8080:8080`)? For another host, allow the permission prompt or use PhishNet 2.4.0+. |
| … didn't answer within 20 seconds | Something is listening there but not replying - is it really a PhishNet API? |
| … answered with HTTP …, not like a PhishNet API | The address points at a different web server. |
| Only regular web pages … can be checked | You opened it on a browser page, a local file, or an extension page. |
| PhishNet API requires an API key / rejected the API key | Paste the key from `phishnet serve` (or `~/.phishnet/api-key` on the server) into Settings → **API key**. If the server's key was replaced, paste the new one. |
| Too many scan requests … | The server's rate limit (60 scans per minute per client by default). Wait the number of seconds shown; the server's admin can change it with `--rate-limit`. |

**Settings → Test connection** is the quickest way to check the address and the key.

## Files

```
manifest.json      Manifest V3, shared by Chrome and Firefox
_locales/          en and tr messages.json: all the extension's text
popup.html/.css/.js   toolbar popup: reads the tab URL, calls the API, shows the result
options.html/.css/.js settings page: API address, API key, language, test connection, reset
lib/api.js         shared: browser/chrome shim, settings storage, API calls and error messages
lib/i18n.js        shared: picks the language and translates the pages
styles.css         shared dark theme
icons/             icon.svg (source) and its 16/32/48/128 px PNG renders
```
