 * Fix Cross-Site Request Forgery (CSRF) vulnerability in all JSON API endpoints.
This was caused because a third-party library doesn't implement proper
Content-Type header validation. To mitigate the vulnerability, we set the
session cookie to have the `SameSite: Lax` property.
 * Fix Faraday Server logs were always in debug
 * Add update date column when exporting vulnerabilities to CSV
 * Fix unicode error when exporting vulnerabilities to CSV
