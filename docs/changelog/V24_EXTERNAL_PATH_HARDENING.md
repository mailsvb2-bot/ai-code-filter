<!-- ai-code-filter-historical-versions: true -->
# v0.25 External Audit Hardening

This release fixes path-portability and archive-name bypass classes found during external review of v0.23.

Key fixes:
- reject Windows reserved device names in manifests, release trees, Markdown links and zip members;
- reject colon/ADS-style paths such as `file:stream`;
- reject trailing-dot/trailing-space path components;
- reject percent-encoded traversal/backslash payloads;
- reject Unicode format-control characters in paths;
- reject overlong path components and overlong relative paths;
- reject double-slash zip member names before `PurePosixPath` normalization;
- detect case-insensitive duplicate zip members.
