 * [FIX] Re-importing an open or re-opened vulnerability now refreshes `last_detected` and `update_date`. #8518
 * [ADD] Added `What's New` section. #8492
 * [FIX] Exporting vulnerabilities to CSV with the Last Detected column no longer returns a 400. #8460
 * [FIX] Fixed pipeline conditions never matching when a choice custom attribute has no valid choices. #8577
 * [ADD] New `GET /vulns/<id>/tools_history` endpoint and a `"Web UI"` fallback for asset creator tool; also fixes command creator not being set on bulk vulnerability updates. #8470
 * [FIX] Fix custom attribute values persisting after deletion when recreated with the same name. #6369
 * [FIX] Vulnerability templates created via file import (CSV or Status Report) now set the creator field. #8245
