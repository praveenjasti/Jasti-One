class GmailConnector:
    # Deliberately disconnected until owner-configured OAuth credentials and scopes are reviewed.
    def status(self):
        return {"connected": False, "message": "Configure a Google OAuth desktop client first."}

    def scan_large_attachments(self, *args, **kwargs):
        raise NotImplementedError("Gmail scan is disabled until OAuth and read-only scopes are configured.")
