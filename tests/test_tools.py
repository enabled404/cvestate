from __future__ import annotations

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

SERVER_PARAMS = StdioServerParameters(
    command="python",
    args=["-m", "cve_mcp.server"],
)

EXPECTED_TOOLS = {
    # Original 8
    "lookup_cve",
    "search_cves",
    "check_package_vulns",
    "get_epss_score",
    "check_kev",
    "parse_cvss",
    "get_cve_summary",
    "health_check",
    # Expansion: network intel
    "check_ip_reputation",
    "get_domain_intel",
    "passive_dns_lookup",
    "shodan_host_lookup",
    # Expansion: threat intel
    "lookup_file_hash",
    "check_url_safety",
    "lookup_malware_family",
    "check_ransomware_intel",
    # Expansion: vuln intel
    "get_vendor_advisory",
    "check_exploit_availability",
    "get_attack_mapping",
    "get_cve_timeline",
    # Expansion: devsecops
    "scan_dependencies",
    "scan_container_packages",
    "scan_repo_secrets",
    # Phase 3: vuln intel + risk
    "check_poc_exists",
    "calculate_risk_score",
    "generate_vuln_report",
    "compare_cves",
}


@pytest.mark.asyncio
async def test_all_tools_registered():
    async with stdio_client(SERVER_PARAMS) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools_resp = await session.list_tools()
            names = {t.name for t in tools_resp.tools}
            assert EXPECTED_TOOLS.issubset(names), f"Missing tools: {EXPECTED_TOOLS - names}"


@pytest.mark.asyncio
async def test_parse_cvss_valid_v31():
    async with stdio_client(SERVER_PARAMS) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(
                "parse_cvss",
                {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
            )
            text = result.content[0].text
            assert "9.8" in text


@pytest.mark.asyncio
async def test_parse_cvss_invalid():
    async with stdio_client(SERVER_PARAMS) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(
                "parse_cvss",
                {"vector": "NOT_A_VECTOR"},
            )
            text = result.content[0].text
            assert "Unsupported" in text


@pytest.mark.asyncio
async def test_health_check():
    async with stdio_client(SERVER_PARAMS) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("health_check", {})
            text = result.content[0].text
            assert "KEV Catalog" in text
