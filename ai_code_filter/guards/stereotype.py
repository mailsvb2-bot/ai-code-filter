from __future__ import annotations

import math
import re
from collections import Counter

FORBIDDEN_PATTERNS = (
    r"\b(интересн(?:ый|ая|о|ые)|важн(?:ый|ая|о|ые)|замечательн(?:ый|ая|о|ые)|хорош(?:ий|ая|о|ие))\b",
    r"\b(следует\s+(?:отметить|рассмотреть|обратить\s+внимание)|рекомендуется|стоит\s+подумать)\b",
    r"\b(возможно,?\s+связано|вероятно,?\s+имеет|кажется,?\s+что)\b",
    r"\b(давайте\s+посмотрим|рассмотрим\s+глубже|это\s+интересный\s+вопрос)\b",
    r"\b(ваш\s+подход|ваше\s+решение|вы\s+абсолютно\s+правы)\b",
)

TECH_KEYWORDS = (
    "логическая ошибка", "условие", "null", "цикл", "асинхронность", "утечка", "sql", "api",
    "сериализация", "безопасность", "solid", "галлюцинация", "архитектура", "валидация", "eval", "xss", "инъекция",
)


def estimate_stereotype_score(text: str) -> float:
    forbidden_count = sum(len(re.findall(pattern, text, re.IGNORECASE)) for pattern in FORBIDDEN_PATTERNS)
    words = re.findall(r"\w+", text.lower())
    if not words:
        return 0.0
    if forbidden_count == 0:
        return 0.0
    forbidden_ratio = forbidden_count / len(words)
    sentences = re.split(r"[.!?]+", text)
    lengths = [len(re.findall(r"\w+", sentence)) for sentence in sentences if sentence.strip()]
    if lengths:
        histogram = Counter(lengths)
        total = len(lengths)
        entropy = -sum((count / total) * math.log2(count / total) for count in histogram.values())
        max_entropy = math.log2(len(histogram)) if len(histogram) > 1 else 1.0
        entropy_ratio = entropy / max_entropy
    else:
        entropy_ratio = 0.0
    tech_ratio = sum(1 for word in TECH_KEYWORDS if word in text.lower()) / len(words)
    raw = max(0.0, forbidden_ratio * 10.0 + entropy_ratio * 5.0 - tech_ratio * 3.0)
    return 1.0 / (1.0 + math.exp(-(raw - 2.0)))


def needs_strict_retry(text: str, threshold: float = 0.7) -> bool:
    return estimate_stereotype_score(text) > threshold
