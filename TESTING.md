# Testing Network Snif Dog

This guide shows you how to test the reverse engineering agent in different ways.

## Prerequisites

Ensure dependencies are installed:
```bash
uv sync
uv run playwright install chromium
```

## Test 1: Standalone Sniffer Test (Quick Validation)

Test just the network capture component:

```bash
# Basic test - capture traffic from any website
uv run python sniffer.py https://example.com

# The output will be JSON of captured XHR/Fetch requests
```

**Note:** Many websites load data server-side (no XHR/Fetch), so you might see empty results. That's normal!

## Test 2: Complete Workflow Test (Recommended)

Test both the sniffer AND the analyzer together:

```bash
# Test on any website
uv run python test_standalone.py https://example.com

# Example output:
# 🐕 Network Snif Dog - Testing on https://example.com
# 📡 Capturing network traffic...
# ✅ Captured 5 API requests
# 🧠 Analyzing traffic...
# 📊 ANALYSIS REPORT
# Total Endpoints: 5
#   - REST API: 3
#   - GraphQL: 0
#   - JSON Data: 2
# ...
```

This will:
1. Launch a browser and capture network traffic
2. Analyze it using the built-in heuristics
3. Show you a formatted report
4. Save full JSON report to `test_report.json`

### Good Test Sites

These sites have rich XHR/Fetch traffic:

**Modern SPAs (Single Page Apps):**
```bash
# GitHub (lots of API calls)
uv run python test_standalone.py https://github.com/explore

# Twitter/X (if accessible)
uv run python test_standalone.py https://twitter.com

# Any React/Vue/Angular app
```

**API Documentation Sites:**
```bash
# Often make live API calls for examples
uv run python test_standalone.py https://docs.anthropic.com
```

**E-commerce Sites:**
```bash
# Product listings trigger API calls
uv run python test_standalone.py https://www.amazon.com
```

## Test 3: MCP Server Test (Full Integration)

This tests the agent as Claude would use it.

### Step 1: Test MCP Server Starts

```bash
# Start the MCP server manually
uv run python server.py
```

You should see no output - it's waiting for MCP protocol messages on stdin/stdout.
Press `Ctrl+C` to stop.

✅ If it doesn't crash, the server works!

### Step 2: Test with MCP Inspector (Optional)

The MCP Inspector is a debugging tool for MCP servers:

```bash
# Install MCP Inspector
npx @modelcontextprotocol/inspector

# When it opens in browser, configure:
# Command: uv
# Args: ["run", "python", "/full/path/to/network-snif-dog/server.py"]
```

You'll see your two tools (`sniff_website` and `analyze_traffic`) listed. You can test them interactively!

### Step 3: Configure Claude Code

Add to `~/.config/claude-code/mcp_config.json`:

```json
{
  "mcpServers": {
    "network-snif-dog": {
      "command": "uv",
      "args": [
        "run",
        "python",
        "/Users/martinlejko/Repos/github.com/martinlejko/network-snif-dog/server.py"
      ]
    }
  }
}
```

**Important:** Replace the path with your actual path.

### Step 4: Restart Claude Code

```bash
# Quit and restart Claude Code
# The MCP server will load automatically
```

### Step 5: Test in Claude Code

Open a chat and type:

```
Can you use the network-snif-dog tools to analyze https://github.com/explore
```

Claude should:
1. Call `sniff_website` tool with the URL
2. Receive the captured network data
3. Call `analyze_traffic` tool with that data
4. Present you with a formatted analysis report

## Test 4: Test with Different Sites

Try analyzing different types of applications:

### REST API Application
```bash
uv run python test_standalone.py https://app.example.com
```
Expected: Multiple endpoints with `/api/v1/` patterns, strong ETags

### GraphQL Application
```bash
uv run python test_standalone.py https://github.com
```
Expected: POST requests to `/graphql` endpoint

### Modern SPA
```bash
uv run python test_standalone.py https://reddit.com
```
Expected: Many JSON_DATA endpoints, some with pagination (Link headers)

## Troubleshooting

### "No XHR/Fetch requests found"

This means the website loads all data server-side (traditional HTML rendering).

**Solutions:**
- Try a different site (modern SPAs work best)
- Check if the site blocks headless browsers
- Try adding `--headed` mode (edit sniffer.py: `headless=False`)

### "Timeout 30000ms exceeded"

The page took too long to load.

**Solutions:**
- Increase timeout in `sniffer.py` (change `timeout` parameter)
- Try a faster/simpler site first
- Check your internet connection

### "Browser executable not found"

Playwright browsers aren't installed.

**Solution:**
```bash
uv run playwright install chromium
```

### MCP Server Not Showing in Claude Code

**Checklist:**
1. Check `mcp_config.json` path is correct (use absolute path)
2. Restart Claude Code completely
3. Check Claude Code logs: `~/.config/claude-code/logs/`
4. Test server starts manually: `uv run python server.py`

## Expected Output Examples

### Successful REST API Discovery
```
📊 ANALYSIS REPORT

Total Endpoints: 8
  - REST API: 6
  - GraphQL: 0
  - JSON Data: 2

🔍 Discovered Endpoints:

1. [REST_API] GET https://api.example.com/v1/users
   Purpose: Retrieves data - User data or authentication endpoint
   ETag: "a7f8c9d..." (type: strong)

2. [REST_API] GET https://api.example.com/v1/products?page=2
   Purpose: Retrieves data - Product/item catalog endpoint
   Pagination: 3 links found (next, prev, last)
```

### Successful GraphQL Discovery
```
📊 ANALYSIS REPORT

Total Endpoints: 1
  - REST API: 0
  - GraphQL: 1
  - JSON Data: 0

🔍 Discovered Endpoints:

1. [GRAPHQL] POST https://api.github.com/graphql
   Purpose: GraphQL API endpoint - handles queries and mutations
```

## Performance Expectations

- **Sniffing time:** 10-30 seconds per site
- **Analysis time:** <1 second (local processing)
- **Memory usage:** ~200-300 MB (Playwright browser)
- **Browser bandwidth:** Depends on site (typically 1-10 MB)

## Next Steps

Once testing is successful:
1. Configure the MCP server in Claude Code (see Step 3 above)
2. Start using Claude to analyze sites naturally
3. Try analyzing your own web applications
4. Extend the heuristics in `server.py` for your specific use case

Happy sniffing! 🐕‍🦺
