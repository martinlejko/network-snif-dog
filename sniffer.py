"""
Playwright-based network traffic sniffer for web application API discovery.
Captures XHR and Fetch requests with full headers and response data.
"""

import asyncio
import json
from typing import List, Dict, Any
from playwright.async_api import async_playwright, Route, Request, Response


class NetworkSniffer:
    """Captures and analyzes network traffic from web applications."""

    def __init__(self):
        self.captured_requests: List[Dict[str, Any]] = []

    async def _handle_route(self, route: Route) -> None:
        """
        Intercept and capture network requests.
        Only captures XHR and Fetch requests to focus on API traffic.
        """
        request: Request = route.request
        resource_type = request.resource_type

        # Filter: only capture API-related requests
        if resource_type in ['xhr', 'fetch']:
            try:
                # Fetch the actual response
                response: Response = await route.fetch()

                # Extract all relevant data
                request_headers = await request.all_headers()
                response_headers = response.headers

                # Get response body (truncate to manage size)
                try:
                    response_body = await response.text()
                    # Truncate to 500 characters to keep token count manageable
                    if len(response_body) > 500:
                        response_body = response_body[:500] + "..."
                except Exception:
                    response_body = None

                # Store captured request data
                captured_data = {
                    "url": request.url,
                    "method": request.method,
                    "resource_type": resource_type,
                    "request_headers": request_headers,
                    "post_data": request.post_data,
                    "response_status": response.status,
                    "response_headers": response_headers,
                    "response_body": response_body
                }

                self.captured_requests.append(captured_data)

                # Fulfill the route to continue normal page behavior
                await route.fulfill(response=response)

            except Exception as e:
                print(f"Error capturing request to {request.url}: {e}")
                # Abort on error to avoid hanging
                await route.abort()
        else:
            # Continue all other requests without processing
            await route.continue_()

    async def sniff(self, target_url: str, timeout: int = 30000) -> List[Dict[str, Any]]:
        """
        Main sniffing function: launches browser, navigates, captures traffic.

        Args:
            target_url: The URL to analyze
            timeout: Maximum time to wait for page load (ms)

        Returns:
            List of captured network requests
        """
        async with async_playwright() as p:
            # Launch browser in headless mode
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            )
            page = await context.new_page()

            # Enable network interception
            await page.route('**/*', self._handle_route)

            try:
                print(f"Navigating to {target_url}...")
                # Navigate and wait for initial network idle
                await page.goto(target_url, wait_until='networkidle', timeout=timeout)

                print("Performing interactive probing...")
                # Interactive probing phase: trigger dynamic content loading

                # 1. Scroll to bottom (triggers infinite scroll, lazy loading)
                await page.evaluate('window.scrollTo(0, document.body.scrollHeight)')
                await asyncio.sleep(2)

                # 2. Wait for any new network requests to complete
                await page.wait_for_load_state('networkidle', timeout=5000)

                # 3. Scroll back to top and wait (some sites load on scroll up)
                await page.evaluate('window.scrollTo(0, 0)')
                await asyncio.sleep(1)

                print(f"Capture complete. Found {len(self.captured_requests)} API requests.")

            except Exception as e:
                print(f"Error during sniffing: {e}")
            finally:
                await browser.close()

        return self.captured_requests


async def sniff_website(url: str) -> List[Dict[str, Any]]:
    """
    Convenience function to sniff a website and return captured traffic.

    Args:
        url: Target website URL

    Returns:
        JSON-serializable list of captured network events
    """
    sniffer = NetworkSniffer()
    captured_data = await sniffer.sniff(url)
    return captured_data


# CLI usage for testing
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python sniffer.py <url>")
        sys.exit(1)

    target_url = sys.argv[1]

    # Run the sniffer
    results = asyncio.run(sniff_website(target_url))

    # Output as JSON
    print("\n=== CAPTURED TRAFFIC ===")
    print(json.dumps(results, indent=2))
