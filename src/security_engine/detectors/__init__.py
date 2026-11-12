from src.security_engine.detectors.base import Detector
from src.security_engine.detectors.brute_force import BruteForceDetector
from src.security_engine.detectors.credential_stuffing import CredentialStuffingDetector
from src.security_engine.detectors.path_probe import PathProbeDetector
from src.security_engine.detectors.payload import PayloadDetector
from src.security_engine.detectors.rate_abuse import RateAbuseDetector
from src.security_engine.detectors.scraping import ScrapingDetector
from src.security_engine.detectors.user_agent_rotation import UserAgentRotationDetector
from src.security_engine.detectors.xss import XSSPayloadDetector


def build_detectors() -> list[Detector]:
    return [
        RateAbuseDetector(),
        BruteForceDetector(),
        PayloadDetector(),
        XSSPayloadDetector(),
        PathProbeDetector(),
        ScrapingDetector(),
        CredentialStuffingDetector(),
        UserAgentRotationDetector(),
    ]


__all__ = [
    "BruteForceDetector",
    "CredentialStuffingDetector",
    "PathProbeDetector",
    "PayloadDetector",
    "RateAbuseDetector",
    "ScrapingDetector",
    "UserAgentRotationDetector",
    "XSSPayloadDetector",
    "build_detectors",
]
