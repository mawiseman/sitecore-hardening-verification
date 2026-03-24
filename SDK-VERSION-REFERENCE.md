# SDK Version Reference

Reference data for Sitecore JSS and Content SDK version detection.

## Source Data

The dependency fingerprints below were extracted from clean installs located at:

```
C:\projects\sitecore-xmcloud-clean\
```

Each subfolder contains an unmodified `npm init` / scaffold output for that SDK version, with `node_modules` intact. The key file analysed in each is `package.json` (for dependency versions) and `src/` (for routing and initialization patterns).

### Versions Analysed

| Folder | SDK Package | Version |
|---|---|---|
| `JSS 21.1.0` | `@sitecore-jss/sitecore-jss-nextjs` | 21.1.0 |
| `JSS 21.6.0` | `@sitecore-jss/sitecore-jss-nextjs` | 21.6.0 |
| `JSS 22.1` | `@sitecore-jss/sitecore-jss-nextjs` | 22.1.4 |
| `JSS 22.1_ssr` | `@sitecore-jss/sitecore-jss-nextjs` | 22.1.4 (SSR variant) |
| `JSS 22.4` | `@sitecore-jss/sitecore-jss-nextjs` | 22.4.1 |
| `JSS 22.5` | `@sitecore-jss/sitecore-jss-nextjs` | 22.5.5 |
| `JSS 22.9.0` | `@sitecore-jss/sitecore-jss-nextjs` | 22.9.0 |
| `ContentSDK 1.2.1` | `@sitecore-content-sdk/nextjs` | 1.2.1 |
| `ContentSDK 1.3.1` | `@sitecore-content-sdk/nextjs` | 1.3.1 |
| `ContentSDK 2.0.1` | `@sitecore-content-sdk/nextjs` | 2.0.1 |

## Full Dependency Fingerprint Table

| Version | Next.js | React | Router | CloudSDK | FEAAS | i18n | CSS | Other |
|---|---|---|---|---|---|---|---|---|
| JSS 21.1.0 | 13.1.6 | 18.2.0 | Pages | None | None | next-localization | Bootstrap 5 | `@sitecore/engage` ^0.4.0 |
| JSS 21.6.0 | 13.4.16 | 18.2.0 | Pages | events ^0.1.3 | ^0.5.12 | next-localization | Bootstrap 5 | First CloudSDK + FEAAS |
| JSS 22.1.4 | 14.2.7 | 18.2.0 | Pages | events ^0.3.1 | ^0.5.17 | next-localization | Bootstrap 5 | Jump to Next 14 |
| JSS 22.4.1 | 14.2.18 | 18.2.0 | Pages | core+events ^0.4.2 | ^0.5.19 | next-localization | Bootstrap 5 | First `@sitecore-cloudsdk/core` |
| JSS 22.5.5 | 14.2.18 | 18.2.0 | Pages | core+events ^0.4.2 | ^0.5.19 | next-localization | Bootstrap 5 | Same CloudSDK as 22.4 |
| JSS 22.9.0 | 15.4.6 | 19.1.0 | Pages | core+events ^0.5.2 | ^0.6.2 | next-localization | Bootstrap 5.2 | Jump to Next 15 + React 19 |
| ContentSDK 1.2.1 | 15.3.2 | 19.1.0 | Pages | core+events ^0.5.1 | ^0.6.0 | next-localization | None | `@sitecore-content-sdk/nextjs` |
| ContentSDK 1.3.1 | 15.5.9 | 19.2.1 | **App** | core+events ^0.5.4 | ^0.6.0 | **next-intl** | **Tailwind 4** | Only App Router version |
| ContentSDK 2.0.1 | **16.1.1** | 19.2.1 | Pages | **None** | ^0.6.0 | next-localization | None | New: `@sitecore-content-sdk/events`, `analytics-core`, `initContentSdk()` |

## Detection Strategy

### Why major-version buckets only

Package-scoped strings like `@sitecore-jss/sitecore-jss-nextjs`, `@sitecore-cloudsdk/events`, and `@sitecore/engage` are **stripped by production minification** (webpack/terser). Minor version differences (21.1 vs 21.6, 22.4 vs 22.5) depend on these strings being present, so they cannot be reliably distinguished in production builds.

### Signals that survive minification

| Signal | Source | What it tells us |
|---|---|---|
| `sitecoreContext` | Bundle (runtime identifier) | JSS family (all versions) |
| `layoutData` | Bundle (runtime identifier) | JSS family (all versions) |
| React version (`18.x` / `19.x`) | Framework chunk (`version:"18.3.1"`) | JSS 21-22 React 18 vs JSS 22.9+ React 19 |
| `__NEXT_DATA__` script tag | HTML | Pages Router (JSS all, ContentSDK 1.2, 2.0) |
| `self.__next_f.push` | HTML | App Router (ContentSDK 1.3) |
| `@sitecore-content-sdk` | Bundle (may survive) | Content SDK family |
| `initContentSdk` | Bundle (runtime call) | Content SDK 2.x specifically |
| `edge.sitecorecloud.io` | Bundle or HTML | XM Cloud deployment |
| Turbopack chunk naming | HTML script srcs | Next.js 16+ (ContentSDK 2.x) |

### Detection buckets

| Label | Covers | Primary Signals |
|---|---|---|
| **JSS 21.x** | 21.1 through 21.7+ | `sitecoreContext` + React 18 |
| **JSS 22.x** | 22.1 through 22.10+ | `sitecoreContext` + React 18 or 19 |
| **Content SDK 1.x** | 1.2, 1.3 | `@sitecore-content-sdk` + CloudSDK present |
| **Content SDK 2.x** | 2.0+ | `@sitecore-content-sdk` + `initContentSdk` + no CloudSDK |

Note: JSS 22.x with React 18 (22.1-22.5) and React 19 (22.9+) are reported under the same label because the React version alone doesn't reliably distinguish them from all edge cases in real-world customised sites.

## Verified Test Sites

See `tests/known-sites.csv` for the current list. Run `node tests/verify-detection.js` to validate.

## Adding New Versions

When a new JSS or Content SDK version is released:

1. Create a clean install in `C:\projects\sitecore-xmcloud-clean\<name>`
2. Run `npm install` to populate `node_modules`
3. Extract the key dependencies from `package.json` and add a row to the fingerprint table above
4. Check if the new version introduces signals that differ from existing buckets
5. If a new bucket is needed, add a candidate to `chrome-extension/checks/jss-version.js`
6. Add a test site to `tests/known-sites.csv` when one is available
7. Run `node tests/verify-detection.js` to confirm no regressions
