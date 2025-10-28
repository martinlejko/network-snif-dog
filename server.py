#!/usr/bin/env python3
"""
Network Snif Dog - MCP Server
An AI-powered web application reverse engineering agent.

Provides two MCP tools:
1. sniff_website: Captures network traffic from a target URL
2. analyze_traffic: Analyzes captured traffic to identify API architecture
"""

import asyncio
import json
import sys
from typing import Any, Dict, List

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from sniffer import sniff_website


# Initialize MCP server
app = Server("network-snif-dog")


@app.list_tools()
async def list_tools() -> list[Tool]:
    """Define available MCP tools."""
    return [
        Tool(
            name="sniff_website",
            description="""
Launches a headless browser to capture network traffic from a target website.
This tool uses Playwright to navigate to the URL, interact with the page (scrolling, etc.),
and capture all XHR and Fetch requests that reveal the site's API architecture.

Returns a JSON array of captured network events, each containing:
- url: The endpoint URL
- method: HTTP method (GET, POST, etc.)
- request_headers: All request headers
- response_status: HTTP status code
- response_headers: All response headers (especially ETag, Link, Content-Type)
- response_body: Truncated response payload

This is the first step in the reverse engineering workflow. After capturing traffic,
use the analyze_traffic tool to extract structured intelligence from the data.
""".strip(),
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "The target website URL to analyze (e.g., https://example.com)"
                    }
                },
                "required": ["url"]
            }
        ),
        Tool(
            name="analyze_traffic",
            description="""
Analyzes captured network traffic to identify and classify API endpoints.
This tool applies expert reverse engineering heuristics to discover the API architecture.

Analysis heuristics:
- REST API Detection: URLs containing /api/, /v1/, /v2/, or plural nouns (e.g., /users, /products)
- GraphQL Detection: POST requests to /graphql endpoint
- JSON Data Endpoints: Any endpoint returning Content-Type: application/json
- ETag Analysis: Strong ETags (no W/ prefix) vs Weak ETags (W/ prefix) for versioning strategy
- Link Header Parsing: Discovers pagination (rel="next", rel="prev") and related resources
- Cache-Control: Identifies caching policies and API maturity

Returns a structured JSON report with:
- discovered_endpoints: Array of classified endpoints
  - endpoint_url: The discovered URL
  - http_method: GET, POST, PUT, DELETE, etc.
  - endpoint_type: REST_API | GRAPHQL | JSON_DATA
  - inferred_purpose: AI-generated description of what the endpoint does
  - response_status_code: HTTP status
  - key_headers: Parsed ETag, Link headers, and Content-Type
  - response_body_snippet: Sample of response data

Input must be the output from sniff_website tool (array of captured requests).
""".strip(),
            inputSchema={
                "type": "object",
                "properties": {
                    "network_data": {
                        "type": "array",
                        "description": "Array of captured network requests from sniff_website tool",
                        "items": {
                            "type": "object"
                        }
                    }
                },
                "required": ["network_data"]
            }
        )
    ]


def parse_etag(etag_value: str) -> Dict[str, str]:
    """
    Parse ETag header to determine if it's strong or weak validation.

    Args:
        etag_value: Raw ETag header value

    Returns:
        Dict with 'value' and 'type' (strong or weak)
    """
    if not etag_value:
        return None

    if etag_value.startswith('W/'):
        return {
            "value": etag_value,
            "type": "weak"
        }
    else:
        return {
            "value": etag_value,
            "type": "strong"
        }


def parse_link_header(link_value: str) -> List[Dict[str, str]]:
    """
    Parse HTTP Link header to extract pagination and related resources.

    Example: '<https://api.example.com?page=2>; rel="next", <...>; rel="prev"'

    Returns:
        List of {rel, url} dictionaries
    """
    if not link_value:
        return []

    links = []
    # Split by comma to get individual links
    for link_part in link_value.split(','):
        link_part = link_part.strip()
        if '<' in link_part and '>' in link_part:
            # Extract URL
            url = link_part[link_part.find('<')+1:link_part.find('>')]
            # Extract rel attribute
            if 'rel=' in link_part:
                rel_part = link_part[link_part.find('rel=')+4:]
                rel = rel_part.strip(' "\'')
                links.append({"rel": rel, "url": url})

    return links


def classify_endpoint(url: str, method: str, headers: Dict[str, str], body: str) -> tuple[str, str]:
    """
    Classify an endpoint and infer its purpose based on URL patterns and headers.

    Returns:
        Tuple of (endpoint_type, inferred_purpose)
    """
    url_lower = url.lower()
    content_type = headers.get('content-type', '').lower()

    # GraphQL detection
    if '/graphql' in url_lower and method == 'POST':
        return ('GRAPHQL', 'GraphQL API endpoint - handles queries and mutations')

    # REST API detection heuristics
    is_rest_api = False
    if any(pattern in url_lower for pattern in ['/api/', '/v1/', '/v2/', '/v3/', '/rest/']):
        is_rest_api = True

    # Check for plural nouns (common REST pattern)
    rest_patterns = ['/users', '/products', '/items', '/posts', '/comments', '/articles',
                     '/orders', '/customers', '/events', '/categories']
    if any(pattern in url_lower for pattern in rest_patterns):
        is_rest_api = True

    # Infer purpose from URL path
    purpose = "Unknown API endpoint"
    if '/user' in url_lower:
        purpose = "User data or authentication endpoint"
    elif '/product' in url_lower or '/item' in url_lower:
        purpose = "Product/item catalog endpoint"
    elif '/search' in url_lower:
        purpose = "Search functionality endpoint"
    elif '/auth' in url_lower or '/login' in url_lower or '/token' in url_lower:
        purpose = "Authentication/authorization endpoint"
    elif '/comment' in url_lower or '/post' in url_lower:
        purpose = "Content creation or social features endpoint"

    # Add method context to purpose
    if method == 'GET':
        purpose = f"Retrieves data - {purpose}"
    elif method == 'POST':
        purpose = f"Creates or submits data - {purpose}"
    elif method == 'PUT' or method == 'PATCH':
        purpose = f"Updates existing data - {purpose}"
    elif method == 'DELETE':
        purpose = f"Deletes data - {purpose}"

    # Determine endpoint type
    if is_rest_api:
        return ('REST_API', purpose)
    elif 'application/json' in content_type:
        return ('JSON_DATA', purpose)
    else:
        return ('JSON_DATA', purpose)


def analyze_captured_traffic(network_data: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Main analysis function: processes captured network data and returns structured report.

    Args:
        network_data: List of captured requests from sniff_website

    Returns:
        Structured analysis report with discovered endpoints
    """
    discovered_endpoints = []

    for event in network_data:
        url = event.get('url', '')
        method = event.get('method', 'GET')
        response_headers = event.get('response_headers', {})
        response_body = event.get('response_body', '')
        response_status = event.get('response_status', 0)

        # Classify the endpoint
        endpoint_type, inferred_purpose = classify_endpoint(
            url, method, response_headers, response_body
        )

        # Extract key headers
        key_headers = {}

        # Parse ETag
        etag = response_headers.get('etag')
        if etag:
            key_headers['etag'] = parse_etag(etag)

        # Parse Link header
        link = response_headers.get('link')
        if link:
            parsed_links = parse_link_header(link)
            if parsed_links:
                key_headers['link_header'] = parsed_links

        # Include Content-Type
        content_type = response_headers.get('content-type')
        if content_type:
            key_headers['content_type'] = content_type

        # Build endpoint entry
        endpoint_entry = {
            "endpoint_url": url,
            "http_method": method,
            "endpoint_type": endpoint_type,
            "inferred_purpose": inferred_purpose,
            "response_status_code": response_status,
            "key_headers": key_headers,
            "response_body_snippet": response_body[:200] if response_body else None
        }

        discovered_endpoints.append(endpoint_entry)

    # Build final report
    report = {
        "discovered_endpoints": discovered_endpoints,
        "summary": {
            "total_endpoints": len(discovered_endpoints),
            "rest_api_count": sum(1 for e in discovered_endpoints if e['endpoint_type'] == 'REST_API'),
            "graphql_count": sum(1 for e in discovered_endpoints if e['endpoint_type'] == 'GRAPHQL'),
            "json_data_count": sum(1 for e in discovered_endpoints if e['endpoint_type'] == 'JSON_DATA')
        }
    }

    return report


@app.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    """
    Handle tool execution requests from MCP client (Claude).

    Args:
        name: Tool name (sniff_website or analyze_traffic)
        arguments: Tool-specific arguments

    Returns:
        List of TextContent results
    """
    if name == "sniff_website":
        url = arguments.get("url")
        if not url:
            return [TextContent(type="text", text="Error: URL parameter is required")]

        try:
            # Run the sniffer
            captured_data = await sniff_website(url)

            # Return as JSON string
            result = {
                "success": True,
                "url": url,
                "captured_requests": len(captured_data),
                "data": captured_data
            }

            return [TextContent(
                type="text",
                text=json.dumps(result, indent=2)
            )]

        except Exception as e:
            return [TextContent(
                type="text",
                text=f"Error sniffing website: {str(e)}"
            )]

    elif name == "analyze_traffic":
        network_data = arguments.get("network_data")
        if not network_data:
            return [TextContent(type="text", text="Error: network_data parameter is required")]

        try:
            # Run analysis
            analysis_report = analyze_captured_traffic(network_data)

            return [TextContent(
                type="text",
                text=json.dumps(analysis_report, indent=2)
            )]

        except Exception as e:
            return [TextContent(
                type="text",
                text=f"Error analyzing traffic: {str(e)}"
            )]

    else:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]


async def main():
    """Run the MCP server."""
    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options()
        )


if __name__ == "__main__":
    asyncio.run(main())
