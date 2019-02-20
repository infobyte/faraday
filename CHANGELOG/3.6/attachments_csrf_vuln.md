Fix CSRF (Cross-Site Request Forgery) vulnerability in vulnerability attachments API.
This allowed an attacker to upload evidence to vulns. He/she required to know the
desired workspace name and vulnerability id so it complicated the things a bit. We
classified this vuln as a low impact one.
