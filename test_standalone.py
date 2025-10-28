#!/usr/bin/env python3
"""
Standalone test script to verify the sniffer and analyzer work correctly.
"""

import asyncio
import json
from sniffer import sniff_website
from server import analyze_captured_traffic

async def test_full_workflow(url: str):
    """Test both sniffer and analyzer together."""

    print(f"🐕 Network Snif Dog - Testing on {url}\n")
    print("=" * 80)

    # Step 1: Sniff the website
    print("\n📡 STEP 1: Capturing network traffic...")
    captured_data = await sniff_website(url)

    print(f"✅ Captured {len(captured_data)} API requests\n")

    if not captured_data:
        print("⚠️  No XHR/Fetch requests found. Try a more dynamic website.")
        print("   Suggestions: https://jsonplaceholder.typicode.com/posts")
        return

    # Show captured requests
    print("📋 Captured requests:")
    for i, req in enumerate(captured_data[:5], 1):
        print(f"  {i}. {req['method']} {req['url'][:60]}...")

    if len(captured_data) > 5:
        print(f"  ... and {len(captured_data) - 5} more")

    # Step 2: Analyze the traffic
    print("\n🧠 STEP 2: Analyzing traffic with built-in heuristics...")
    analysis_report = analyze_captured_traffic(captured_data)

    print("=" * 80)
    print("\n📊 ANALYSIS REPORT\n")

    # Print summary
    summary = analysis_report.get('summary', {})
    print(f"Total Endpoints: {summary.get('total_endpoints', 0)}")
    print(f"  - REST API: {summary.get('rest_api_count', 0)}")
    print(f"  - GraphQL: {summary.get('graphql_count', 0)}")
    print(f"  - JSON Data: {summary.get('json_data_count', 0)}")

    # Print endpoint details
    print("\n🔍 Discovered Endpoints:\n")
    for i, endpoint in enumerate(analysis_report.get('discovered_endpoints', [])[:5], 1):
        print(f"{i}. [{endpoint['endpoint_type']}] {endpoint['http_method']} {endpoint['endpoint_url'][:60]}")
        print(f"   Purpose: {endpoint['inferred_purpose']}")

        # Show key headers if present
        key_headers = endpoint.get('key_headers', {})
        if 'etag' in key_headers:
            etag = key_headers['etag']
            print(f"   ETag: {etag['value'][:30]}... (type: {etag['type']})")
        if 'link_header' in key_headers:
            links = key_headers['link_header']
            print(f"   Pagination: {len(links)} links found")
        print()

    if len(analysis_report.get('discovered_endpoints', [])) > 5:
        remaining = len(analysis_report['discovered_endpoints']) - 5
        print(f"... and {remaining} more endpoints\n")

    # Save full report
    output_file = "test_report.json"
    with open(output_file, 'w') as f:
        json.dump(analysis_report, f, indent=2)

    print(f"💾 Full report saved to: {output_file}")
    print("=" * 80)

if __name__ == "__main__":
    import sys

    # Use command line argument or default test URL
    test_url = sys.argv[1] if len(sys.argv) > 1 else "https://jsonplaceholder.typicode.com"

    asyncio.run(test_full_workflow(test_url))
