    def check_fingerprint(self) -> dict[str, Any]:
        """Measure this client's real fingerprint against the captured target."""
        return verify_fingerprint(self.session)

    def _origin(self, captured: str) -> str:
        """The origin this endpoint was captured on.

        base_url overrides the primary host only; the site's other hosts keep
        the origin they were captured on, so a call to search.* is not sent to
        www.* merely because that one sorted first.
        """
        if captured == self._primary:
            return self.base_url
        return captured.rstrip("/")
