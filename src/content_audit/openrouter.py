"""Клиент OpenRouter для модельных проверок."""

from __future__ import annotations

import json
import time
from typing import Any

import requests


class OpenRouterError(RuntimeError):
    """Ошибка обращения к OpenRouter."""


class OpenRouterClient:
    """Тонкий клиент для запросов к модели через OpenRouter."""

    def __init__(self, api_key: str, model: str, timeout_seconds: float = 60.0) -> None:
        self.api_key = api_key
        self.model = model
        self.timeout_seconds = timeout_seconds

    def complete_json(self, system_prompt: str, user_prompt: str, max_retries: int = 2) -> dict[str, Any]:
        """Запрашиваем у модели JSON и разбираем ответ в словарь."""

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "response_format": {"type": "json_object"},
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        last_error: Exception | None = None
        for attempt in range(max_retries + 1):
            try:
                response = requests.post(
                    "https://openrouter.ai/api/v1/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=self.timeout_seconds,
                )
                response.raise_for_status()
                content = response.json()["choices"][0]["message"]["content"]
                return json.loads(content)
            except Exception as exc:  # noqa: BLE001 - сохраняем любую ошибку провайдера.
                last_error = exc
                if attempt < max_retries:
                    time.sleep(1.5 * (attempt + 1))

        raise OpenRouterError(f"Не удалось получить JSON от OpenRouter: {last_error}")
