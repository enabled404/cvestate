# Contributing to CVE MCP Server

Thank you for your interest in contributing! This document covers how to add new tools, fix bugs, and submit pull requests.

## Quick start for contributors

```bash
git clone https://github.com/enabled404/cvestate.git
cd cvestate
python -m venv venv && source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -e ".[test]"
pip install ruff mypy
cp .env.example .env  # Add API keys for the tools you're testing
```

## Adding a new tool

1. Add the tool function in `src/cve_mcp/server.py` using the `@mcp.tool()` decorator
2. Implement the API client in `src/cve_mcp/api/`
3. Validate input via `src/cve_mcp/utils/validators.py`
4. Route all HTTP through the shared `httpx.AsyncClient` (handles rate limiting, retries, caching)
5. Add tests in `tests/` — offline (mocked) tests are required; live API tests are optional and marked `@pytest.mark.online`
6. Update the README tool catalog table
7. Add any new API key to `.env.example` with a comment

```python
@mcp.tool()
async def my_new_tool(param: str, ctx: Context = None) -> str:
    """
    One-line description for Claude to know when to use this tool.

    Args:
        param: Description of the parameter
    """
    app = _get_app(ctx)
    # validate → cache check → API call → cache write → audit → return
```

## Code standards

- **Python 3.10+** syntax — use `X | Y` union types
- **Async everywhere** — all I/O operations must be `async def`
- **Type hints on all functions**
- **ruff** for linting and formatting: `ruff check . && ruff format .`
- **No bare `except:`** — catch specific exception types
- **defusedxml** for any XML parsing — never `xml.etree.ElementTree` directly on untrusted input
- Private/reserved IPs must be blocked before any external network lookup

## Running the full quality check locally

```bash
ruff check . && ruff format --check . && python -m pytest tests/ -v -m "not online"
```

## Commit message format

```
type(scope): short description

Longer explanation if needed (wrap at 72 chars).

Closes #123
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `chore`, `security`

## Submitting a PR

1. Fork the repo and create a branch from `main`
2. Make your changes following the code standards above
3. Ensure all offline tests pass
4. Fill out the pull request template completely
5. Open the PR against `main`
