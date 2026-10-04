# TeamBrowser identity

Version 1 · 3 October 2026

## Direction

**TeamBrowser** keeps the existing product name and its calm forest, paper, and lime palette. The new **Shared Frame** emblem replaces the temporary three-bar mark. Two offset browser-frame shapes meet around a shared center: a compact visual expression of separate contexts brought into one workspace.

The symbol geometry is original to this project. The wordmark is a fixed outlined rendering of Noto Sans Bold version 2.004 with adjusted tracking; it has no runtime font dependency. The source font metadata identifies Copyright 2015 Google LLC and SIL Open Font License 1.1. No font binary is included. The [official OFL artwork guidance](https://openfontlicense.org/ofl-faq/) permits this logo use (questions 1.1–1.1.2). This is a production-ready asset proposal, not a claim of trademark clearance, name availability, or registered rights. The name is unchanged; no external publication has been performed by the brand work.

## Files

All production assets live in `src/team_browser/static/brand/`.

| Asset | Use |
| --- | --- |
| `logo.svg` | Forest symbol + wordmark on white or paper |
| `logo-reverse.svg` | Lime symbol + paper wordmark on forest |
| `logo-mono.svg` | Single-color inline SVG; inherits `currentColor` |
| `mark.svg` | Forest emblem |
| `mark-reverse.svg` | Lime emblem for dark backgrounds |
| `mark-mono.svg` | Single-color inline emblem; inherits `currentColor` |
| `mark-path.txt` | Canonical 64 × 64 path for byte-conscious inline use |
| `favicon.svg` | Rounded forest tile, optically enlarged emblem |
| `favicon-16.png`, `favicon-32.png`, `favicon-48.png` | Raster favicon fallbacks |
| `favicon.ico` | One container with 16, 32, and 48 px entries |
| `apple-touch-icon.png` | 180 × 180 mobile home-screen icon |
| `app-icon-192.png`, `app-icon-512.png` | Web-app icon sizes; no manifest or installability implied |
| `app-icon.svg` | Full-bleed 1024 × 1024 app tile master |
| `app-icon-macos.svg` | Native master with transparent outer padding |
| `app-icon-macos-1024.png` | Native 1024 × 1024 RGBA export |
| `TeamBrowser.iconset/` | Standard 16, 32, 128, 256, and 512 px @1x/@2x Mac sources |
| `TeamBrowser.icns` | Multi-resolution macOS app icon container |
| `brand-tokens.css` | Opt-in shared palette and namespaced identity classes |

The mark SVG is 413 bytes; the outlined horizontal logo is 6,329 bytes. The logo has a `0 0 277 64` viewBox. The emblem has a `0 0 64 64` viewBox. Standard files are deliberately uncompressed and inspectable.

## Recommended integration

### App and marketing chrome

- Keep the symbol and wordmark on one line. For ordinary headers and sidebar branding, render the lockup at **40 px high**, about **173 px wide**. On narrow surfaces, use the emblem alone at **24–32 px**.
- Use `logo.svg` on paper and `logo-reverse.svg` on forest. Standalone `currentColor` SVG files do not inherit the parent page's text color through an `<img>` element; inline the mono version when inheritance is needed.
- Prefer relative asset URLs in the local app so its `/preview/` and exported-preview routes both work.
- A linked logo must have one accessible name. If the link already has an `aria-label`, its image can have `alt=""`; otherwise use `alt="TeamBrowser"`. Repeated decorative marks use an empty alt attribute. Do not create duplicate spoken labels.
- Set explicit width and height to prevent layout shifts. Preserve aspect ratio; never stretch the mark or logo.
- Suggested app markup: `<a class="brand" href="#profiles" aria-label="TeamBrowser home"><img src="./brand/logo-reverse.svg" width="173" height="40" alt=""></a>`.
- Suggested favicon tags: `<link rel="icon" type="image/svg+xml" href="./brand/favicon.svg">` and `<link rel="icon" sizes="32x32" type="image/png" href="./brand/favicon-32.png">`.
- Use the emblem for application identity. Do not use it as a back button, close icon, profile-specific avatar, or status indicator.

### Asset packaging

The Python package currently uses a static package-data glob. Its owner must include the new `static/brand/*` and `static/brand/TeamBrowser.iconset/*` assets if packaging the full bundle. A preview exporter must preserve `brand/` paths recursively. An app `.app` bundle can use `TeamBrowser.icns` and the corresponding `CFBundleIconFile` value through its native packaging owner. Supplying an `.icns` file does not itself prove the native bundle has adopted it.

The sales project's build is a bounded generated-function asset map, not an automatic directory server. A mirror of the web assets is provided under `team-browser-sales/public/brand/`. Its owner must add only required asset routes or inline the 284-byte canonical emblem path. Do not embed PNGs or the Mac icon container into the 96,000-byte sales-function budget. The small emblem plus text is the most economical option. If adding the full outlined logo, explicitly recheck the function budget. Change the existing root favicon only as part of that integration.

### Native app icon

Use `TeamBrowser.icns` for the macOS app bundle. Keep its transparent padding; do not use the full-bleed web tile in the Dock. The master is flat forest with a lime emblem and a restrained 1 px light edge at 1024 px. No gradients, bitmap sources, or external services are used. Test the actual `.app` icon in the Dock and Finder on macOS after packaging; this Linux-based asset review cannot certify that OS-level integration.

## Palette and accessibility

| Token | Hex | Intended use |
| --- | --- | --- |
| Forest | `#172d27` | Dark surfaces and primary identity |
| Ink | `#1d332b` | Headings and ordinary copy |
| Paper | `#f5f7f3` | App canvas and marketing background |
| White | `#ffffff` | Elevated surfaces and reverse button text |
| Lime | `#d3edb5` | Selected state and reverse symbol |
| Action | `#345d44` | Filled controls |
| Muted | `#617268` | Small secondary text |
| Line | `#e3e9e0` | Decorative dividers |
| Focus | `#55703c` | Focus ring on light backgrounds |

Measured WCAG relative-luminance contrast:

- Forest / Paper: **13.52:1**
- Lime / Forest: **11.48:1**
- Ink / Paper: **12.48:1**
- White / Action: **7.51:1**
- Muted / Paper: **4.73:1**
- Focus / Paper: **5.17:1**

The prior `#687970` muted tone measures **4.27:1** on paper. Use the updated token for small text. The lime and line colors are not text colors on light surfaces. Decorative dividers do not identify focus, selection, or control boundaries alone. Recheck contrast when adding colors or changing surfaces. These brand-pair checks are not a full application accessibility audit.

## Type, space, and motion

- The identity SVG contains outlined letters. Keep UI text live and selectable.
- Preserve the existing native/system UI stack: `Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif`. This does not download or guarantee Inter.
- Favor medium or semibold headings with restrained tracking. Avoid the heavy brand wordmark weight for tables and routine controls.
- Keep at least **8 units** of clear space around the 64-unit emblem and **10 px** between a 32 px emblem and live brand text. Its intrinsic viewBox already includes a 10-unit margin.
- Use the small emblem at 16 px only for favicons; prefer at least 24 px in interactive chrome. At compact sizes, omit a subtitle instead of squeezing the wordmark.
- Keep marks stationary in everyday chrome. If animated in a future launch film, move the two frames into alignment as whole units and respect reduced-motion preferences. Existing film assets are intentionally unchanged.
- Do not add gradients, glow, beveled outlines, drop shadows inside the logo, arbitrary colors, rotations, or new proportions.

## Validation and evidence

The asset review passed **28 file checks**: SVG structure, standalone accessible labels, no script/foreign-object/external references, every PNG's decode/size/alpha, ICO sizes, and ICNS decode/representations. The iconset has all ten standard @1x/@2x PNG sources. All six recommended foreground/background pairs exceed 4.5:1.

Visual inspection covered light and dark lockups, native icon, 16/24/32/48/64 px emblem scale, and the 16/32/48 px raster favicons at actual size and nearest-neighbor enlargement. Generated SVG and raster proof sheets are retained alongside build and validation sources in the shared brand-work deliverable folder. The application study is labeled as an identity placement study, not a screenshot of released functionality.

This validation covers brand assets. Application tests, wheel/export contents, the actual macOS app icon, sales-function size, live routes, and deployment remain the integration owners' verification responsibilities.
