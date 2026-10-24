## Summary

<!-- One paragraph describing what this PR does and why -->

## Type of change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New tool (adds a new MCP tool)
- [ ] New API integration (adds a new external data source)
- [ ] Performance improvement
- [ ] Documentation update
- [ ] Dependency update
- [ ] Breaking change

## Related issue

Closes #

## Testing

- [ ] I have added offline tests (mocked API responses) for new tools
- [ ] I have verified private IP blocking for any new network tools
- [ ] I have run `python -m pytest tests/ -v` and all tests pass
- [ ] I have tested with at least one MCP client (Claude Desktop or Claude Code)

## API keys

- [ ] Any new API keys are documented in `.env.example` with instructions
- [ ] New keys are added to the API Keys Setup section of README.md
- [ ] The tool degrades gracefully when the key is missing

## Checklist

- [ ] All I/O operations are `async def`
- [ ] Input validation uses the existing validator utilities
- [ ] Private/reserved IPs are blocked for any network lookup tools
- [ ] No API keys or sensitive data appear in logs, cache, or audit entries
- [ ] README.md tool catalog is updated if a new tool was added
- [ ] `defusedxml` is used for any XML parsing (never `xml.etree.ElementTree` directly)
