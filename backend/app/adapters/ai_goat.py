from urllib.parse import urlsplit

import httpx

from app.core.config import settings


LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


def _origin(url: str) -> tuple[str, str, int | None]:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()

    # localhost, 127.0.0.1 and ::1 are the same machine.
    if host in LOOPBACK_HOSTS:
        host = "loopback"

    default_port = {"http": 80, "https": 443}.get(parts.scheme)

    return parts.scheme, host, parts.port or default_port


class AIGoatError(Exception):
    pass


class AIGoatAdapter:

    # AI Goat's /api/chat/ is stateless: it wraps each message as
    # "User: {message}\nCracky:" and keeps no history. Multi-turn
    # conversations are replayed as a transcript inside the message,
    # which yields the same prompt a stateful chat would build.
    USER_LABEL = "User"
    ASSISTANT_LABEL = "Cracky"

    # Keeps replayed transcripts within the target's context window.
    MAX_HISTORY_TURNS = 10

    def __init__(self, base_url: str):
        """
        base_url: the target application's endpoint_url (no path),
        e.g. http://127.0.0.1:8001.
        """

        self.base_url = base_url.rstrip("/")

        # AIGOAT_TOKEN is only sent to the AI Goat instance it was issued
        # for. Sending it to any user-supplied endpoint_url would let
        # anyone capture it by pointing an application at their own server.
        if _origin(self.base_url) == _origin(settings.AIGOAT_BASE_URL):
            self.token = settings.AIGOAT_TOKEN
        else:
            self.token = ""

    @classmethod
    def build_message(
        cls,
        message: str,
        history: list[tuple[str, str]] | None = None,
    ) -> str:
        """
        history: previous (user message, assistant reply) turns, oldest first.
        """

        if not history:
            return message

        lines = []

        for index, (user_message, reply) in enumerate(
            history[-cls.MAX_HISTORY_TURNS:]
        ):
            # AI Goat already prefixes the first line with "User: ".
            if index > 0:
                lines.append(f"{cls.USER_LABEL}: {user_message}")
            else:
                lines.append(user_message)

            lines.append(f"{cls.ASSISTANT_LABEL}: {reply}")

        lines.append(f"{cls.USER_LABEL}: {message}")

        return "\n".join(lines)

    def chat(
        self,
        message: str,
        history: list[tuple[str, str]] | None = None,
    ) -> dict:

        message = self.build_message(message, history)

        url = f"{self.base_url}/api/chat/"

        headers = {
            "Content-Type": "application/json",
        }

        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        payload = {
            "message": message,
        }

        try:
            response = httpx.post(
                url,
                headers=headers,
                json=payload,
                timeout=60.0,
            )
        except httpx.RequestError as exc:
            raise AIGoatError(
                f"Unable to connect to AI Goat: {exc}"
            ) from exc

        if response.status_code != 200:
            raise AIGoatError(
                f"AI Goat returned HTTP {response.status_code}: "
                f"{response.text}"
            )

        try:
            return response.json()
        except ValueError as exc:
            raise AIGoatError(
                "AI Goat returned an invalid JSON response"
            ) from exc