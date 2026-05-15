<!-- ai-code-filter-historical-versions: true -->
# AI Code Filter v38 — external audit fixes

Fixed 27 real defects/edge-case gaps found in previous-release external audit:

1. Manifest accepted nested leading-space path components, e.g. `pkg/ evil.txt`.
2. Manifest accepted nested NBSP-leading path components.
3. Manifest accepted nested `~` home-shorthand components.
4. Manifest accepted Unicode fullwidth-dot traversal-like components.
5. Manifest accepted Unicode fullwidth colon / ADS-like components.
6. Manifest accepted Unicode private/unassigned/noncharacter path code points.
7. Manifest collision key used NFC, not NFKC, missing fullwidth ASCII collisions.
8. Manifest percent-decoding separator depth was too shallow for deeper encoded payloads.
9. Tree integrity missed nested leading-space path components.
10. Tree integrity missed nested NBSP-leading path components.
11. Tree integrity missed nested `~` components.
12. Tree integrity missed Unicode fullwidth-dot traversal-like components.
13. Tree integrity missed Unicode fullwidth colon / ADS-like components.
14. Tree integrity missed Unicode private/unassigned/noncharacter path code points.
15. Tree integrity collision detection used NFC, not NFKC.
16. generate-manifest could emit paths with NFKC collisions.
17. Zip audit missed nested leading-space path components.
18. Zip audit missed nested NBSP-leading path components.
19. Zip audit missed nested `~` components.
20. Zip audit missed Unicode fullwidth-dot traversal-like components.
21. Zip audit missed Unicode fullwidth colon / ADS-like components.
22. Zip audit missed Unicode private/unassigned/noncharacter path code points.
23. Zip audit collision detection used NFC, not NFKC.
24. JSON validator accepted non-standard constants such as `NaN`.
25. YAML-like validator missed duplicate keys inside inline maps.
26. Markdown validator missed unquoted HTML HTML link/source attributes targets.
27. Version/docs/tests were updated to v0.38.0 and regression tests were added.
