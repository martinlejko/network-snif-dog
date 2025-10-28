# Network Snif Dog 🐕‍🦺

An AI-powered web application reverse engineering agent that automatically discovers and documents API architectures by analyzing network traffic.

## Overview

Network Snif Dog is a Model Context Protocol (MCP) server that combines Playwright browser automation with intelligent analysis to reverse engineer web applications. It captures network traffic, identifies API endpoints, classifies their architecture (REST, GraphQL), and extracts versioning and pagination strategies from HTTP headers.

**Key Features:**
- Automated network traffic capture using Playwright
- Interactive probing (scrolling, clicking) to trigger dynamic API calls
- ETag header analysis for versioning strategy detection
- Link header parsing for pagination discovery
- REST vs GraphQL endpoint classification
- Structured JSON output for downstream processing

## Architecture

This agent follows a two-subsystem design:

1. **Data Collection (sniffer.py)**: Playwright-based browser automation that captures XHR/Fetch requests
2. **Analysis Engine (server.py)**: MCP server with built-in heuristics for API classification

## Installation

### Prerequisites
- Python 3.8+
- Node.js (for Playwright browser binaries)

### Setup Steps

1. **Clone the repository**
   ```bash
   git clone https://github.com/martinlejko/network-snif-dog.git
   cd network-snif-dog
   ```

2. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Install Playwright browsers**
   ```bash
   playwright install chromium
   ```

4. **Configure Claude Code MCP**

   Add to your Claude Code MCP configuration file (`~/.config/claude-code/mcp_config.json`):

   ```json
   {
     "mcpServers": {
       "network-snif-dog": {
         "command": "python",
         "args": ["/absolute/path/to/network-snif-dog/server.py"]
       }
     }
   }
   ```

   **Important:** Replace `/absolute/path/to/network-snif-dog` with the actual path on your system.

5. **Restart Claude Code**
   ```bash
   # The MCP server will be loaded automatically
   ```

## Usage

### Via Claude Code (Recommended)

Once configured, interact with Claude Code naturally:

```
You: "Analyze the API architecture of https://jsonplaceholder.typicode.com"

Claude: I'll use the network-snif-dog MCP server to analyze this site.

        [Calls sniff_website tool]
        [Captures network traffic]
        [Calls analyze_traffic tool]

        === Analysis Report ===

        Discovered 6 REST API endpoints:

        1. GET /posts
           - Type: REST_API
           - Purpose: Retrieves data - Content creation or social features endpoint
           - ETag: Strong validation (caching enabled)

        2. GET /users/1
           - Type: REST_API
           - Purpose: Retrieves data - User data or authentication endpoint
           ...
```

### Standalone Testing (Development)

Test the sniffer independently:

```bash
python sniffer.py https://example.com
```

This will output captured network traffic as JSON.

## MCP Tools

### 1. `sniff_website`

Captures network traffic from a target URL.

**Input:**
- `url` (string): Target website URL

**Output:**
```json
{
  "success": true,
  "url": "https://example.com",
  "captured_requests": 15,
  "data": [
    {
      "url": "https://api.example.com/users",
      "method": "GET",
      "response_status": 200,
      "response_headers": {
        "etag": "W/\"abc123\"",
        "content-type": "application/json"
      },
      "response_body": "{\"users\": [...]}"
    }
  ]
}
```

### 2. `analyze_traffic`

Analyzes captured traffic to identify API architecture.

**Input:**
- `network_data` (array): Output from `sniff_website` tool

**Output:**
```json
{
  "discovered_endpoints": [
    {
      "endpoint_url": "https://api.example.com/users",
      "http_method": "GET",
      "endpoint_type": "REST_API",
      "inferred_purpose": "Retrieves data - User data or authentication endpoint",
      "response_status_code": 200,
      "key_headers": {
        "etag": {
          "value": "W/\"abc123\"",
          "type": "weak"
        },
        "content_type": "application/json"
      }
    }
  ],
  "summary": {
    "total_endpoints": 6,
    "rest_api_count": 5,
    "graphql_count": 0,
    "json_data_count": 1
  }
}
```

## Analysis Heuristics

The agent uses the following expert heuristics for classification:

### REST API Detection
- URL contains `/api/`, `/v1/`, `/v2/`, `/rest/`
- URL uses plural nouns: `/users`, `/products`, `/items`

### GraphQL Detection
- POST requests to `/graphql` endpoint
- Request body contains `query` or `mutation`

### ETag Analysis
- **Strong ETags** (no `W/` prefix): Byte-for-byte identical content, ideal for static assets
- **Weak ETags** (`W/` prefix): Semantically equivalent, used for dynamic content

### Link Header Parsing
- Extracts pagination: `rel="next"`, `rel="prev"`, `rel="first"`, `rel="last"`
- Discovers related resources and API documentation links

## Technical Details

### Interactive Probing Strategy

The sniffer performs the following actions to trigger dynamic API calls:

1. Navigate to URL and wait for network idle
2. Scroll to bottom (triggers infinite scroll, lazy loading)
3. Wait for new network requests
4. Scroll back to top (some sites load on scroll up)

### Token Optimization

- Response bodies truncated to 500 characters
- Only XHR/Fetch requests captured (ignores images, CSS, fonts)
- Headers filtered to key signals (ETag, Link, Content-Type, Cache-Control)

## Limitations & Future Enhancements

**Current limitations:**
- No support for authenticated endpoints (yet)
- Fixed probing strategy (no adaptive interaction)
- No WebSocket traffic capture

**Planned features:**
- Authentication support (cookies, tokens)
- AI-driven adaptive probing (Claude suggests interactions)
- WebSocket protocol analysis
- API documentation generation

## Contributing

This is a minimal POC. Contributions welcome!

## License

MIT License - see LICENSE file for details

## Acknowledgments

Built using:
- [Anthropic Claude](https://www.anthropic.com) - AI analysis
- [Playwright](https://playwright.dev) - Browser automation
- [Model Context Protocol](https://modelcontextprotocol.io) - Claude integration

Inspired by the architectural blueprint from the original reverse engineering research document.
