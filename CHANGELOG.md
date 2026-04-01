## v0.2.0 (2026-04-01)


- ci: add commitizen for automated version bumping
- Set up commitizen for automatic version management with conventional
commits. On merge to main, detect unreleased changes and auto-bump
version with changelog generation and v-prefixed tags.
- - Add .cz.toml config with v${version} tag format
- Add scripts/bump.py for version bumping with push retry logic
- Add main.yml workflow for auto-bump on merge
- Add commit validation to CI for pull requests
- Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
- feat!: detailed error reporting for token exchange failures
- Port structured error reporting from Python SDK (keycardai/python-sdk#80).
- OAuth layer:
- Token exchange HTTP errors now return *OAuthError with ErrorCode,
  Message (error_description), and ErrorURI instead of fmt.Errorf
- Added test for non-JSON error responses
- MCP layer:
- ErrorDetail: rename Error field to Message, add Code and Description
  fields for structured OAuth error info
- GetErrors() named return: resourceErrors → resources
- ExchangeTokens uses errors.As to extract OAuthError fields into
  ErrorDetail, or RawError from generic errors
- BREAKING CHANGE: ErrorDetail.Error renamed to ErrorDetail.Message
(JSON key: "error" → "message"), new Code/Description fields added
- Refs: AGE-58
- Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
