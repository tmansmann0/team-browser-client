# Read-only runner window classification

The normal-HOME comparison in run 37320168856 stopped before launching the candidate because its preflight saw an unexpected window. SecurityAgent was absent, the window query was available, and no permission-like title was observed. The retained booleans do not identify that window or establish that a permission prompt existed. No cookie or native storage result was obtained.

This separate manual workflow collects one bounded, read-only on-screen window-metadata snapshot on a fresh standard GitHub-hosted macOS 15 Apple Silicon runner. It never downloads or launches TeamBrowser, invokes a Keychain API, interacts with a window, requests a permission, or changes the comparison guard.

The helper reports at most 32 window rows with bounded sanitized owner names, numeric layers, title-availability and permission-like-title booleans, guard classifications, and numeric dimensions when available. It never emits raw window titles, screen positions, screenshots, profile data, Keychain items, paths or credentials. The final JSON is capped at 32 KiB and retained for one day.

This is a new runner snapshot: matching observations can support a cause for the earlier stop but cannot prove the exact identity of that earlier transient window. The output informs a separately reviewed test proposal. It does not automatically rerun the candidate, permit prompts, weaken a guard, or establish native acceptance.
