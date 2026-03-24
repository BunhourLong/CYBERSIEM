from __future__ import annotations

from abc import ABC, abstractmethod

from src.core.http_models import DetectionAlert, HTTPLogEvent


class Detector(ABC):
    @abstractmethod
    def evaluate(self, event: HTTPLogEvent) -> list[DetectionAlert]:
        raise NotImplementedError
