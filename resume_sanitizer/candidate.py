from __future__ import annotations

import re
from dataclasses import dataclass

from resume_sanitizer.models import PIIEntity, PageTextBlock

# Job boards / platforms — never treat as a person's name
PLATFORM_WHITELIST = frozenset({
    "linkedin", "naukri", "indeed", "monster", "glassdoor", "shine", "instahyre",
    "hirist", "foundit", "timesjobs", "internshala", "wellfound", "angellist",
    "stackoverflow", "github", "gitlab", "bitbucket", "twitter", "facebook",
    "instagram", "whatsapp", "telegram", "google", "amazon", "microsoft", "meta",
    "apple", "netflix", "uber", "flipkart", "swiggy", "zomato", "paytm",
})

URL_ENTITY_TYPES = frozenset({
    "LINKEDIN_URL", "GITHUB_URL", "SOCIAL_MEDIA_URL", "SOCIAL_LINK_GROUP", "PERSONAL_URL",
})


@dataclass(frozen=True)
class CandidateProfile:
    """Resolved identity of the resume owner — only this name gets redacted."""
    full_name: str
    name_parts: tuple[str, ...]


def _name_parts(name: str) -> tuple[str, ...]:
    return tuple(p for p in re.split(r"\s+", name.strip()) if len(p) >= 3)


def _name_from_email(email: str) -> str | None:
    user = email.split("@", 1)[0]
    tokens = [t for t in re.split(r"[._\-+]", user) if len(t) >= 2 and t.isalpha()]
    if len(tokens) >= 2:
        return " ".join(tokens[:2]).title()
    if len(user) >= 3 and user.isalpha():
        return user.title()
    return None


def _name_from_linkedin_slug(text: str) -> str | None:
    match = re.search(r"linkedin\.com/in/([A-Za-z0-9\-_%]+)", text, re.I)
    if not match:
        return None
    slug = match.group(1).replace("-", " ").replace("_", " ").strip()
    return slug.title() if len(slug) >= 3 else None


def build_candidate_profile(
    blocks: list[PageTextBlock],
    sections: dict[str, tuple[int, int]],
    entities: list[PIIEntity],
    header_name: PIIEntity | None,
) -> CandidateProfile | None:
    """Infer the candidate's name from header, contact block, email, and profile URLs."""
    name_candidates: list[str] = []

    if header_name:
        name_candidates.append(header_name.text.strip())

    block_offsets: dict[int, int] = {}
    offset = 0
    for block in blocks:
        block_offsets[block.page_number] = offset
        offset += len(block.text) + 2

    contact = sections.get("CONTACT")
    for entity in entities:
        abs_start = block_offsets.get(entity.page, 0) + entity.start
        in_contact = bool(contact and contact[0] <= abs_start < contact[1])
        if not contact and entity.page == 1:
            in_contact = abs_start < 600

        if entity.entity_type == "PERSON" and in_contact:
            name_candidates.append(entity.text.strip())
        elif entity.entity_type == "EMAIL_ADDRESS" and in_contact:
            derived = _name_from_email(entity.text)
            if derived:
                name_candidates.append(derived)
        elif entity.entity_type in URL_ENTITY_TYPES:
            derived = _name_from_linkedin_slug(entity.text)
            if derived:
                name_candidates.append(derived)

    if not name_candidates:
        return None

    if header_name:
        full_name = header_name.text.strip()
    else:
        multi = [n for n in name_candidates if " " in n]
        full_name = max(multi or name_candidates, key=len)

    parts = _name_parts(full_name)
    if not parts:
        return None
    return CandidateProfile(full_name=full_name, name_parts=parts)


def is_candidate_name(text: str, profile: CandidateProfile) -> bool:
    """True only when text matches the resume owner's name (not other people/places)."""
    cleaned = text.strip()
    if not cleaned:
        return False
    if cleaned.lower() == profile.full_name.lower():
        return True

    words = cleaned.split()
    profile_lower = profile.full_name.lower()
    parts_lower = {p.lower() for p in profile.name_parts}

    if len(words) >= 2:
        joined = " ".join(words).lower()
        if joined == profile_lower:
            return True
        return all(w.lower() in parts_lower for w in words)

    if len(cleaned) >= 3 and cleaned.lower() in parts_lower:
        return True
    return False


def is_platform_name(text: str) -> bool:
    return text.strip().lower().rstrip(".,;:") in PLATFORM_WHITELIST


def find_candidate_name_occurrences(
    blocks: list[PageTextBlock],
    profile: CandidateProfile,
    min_confidence: float,
) -> list[PIIEntity]:
    """Find every occurrence of the candidate's name across the full resume."""
    found: list[PIIEntity] = []
    patterns: list[tuple[str, float]] = [(profile.full_name, 0.90)]
    for part in profile.name_parts:
        if part.lower() not in PLATFORM_WHITELIST:
            patterns.append((part, 0.82))

    for block in blocks:
        for pattern, score in patterns:
            if score < min_confidence:
                continue
            for match in re.finditer(re.escape(pattern), block.text, re.IGNORECASE):
                found.append(PIIEntity(
                    entity_type="PERSON",
                    text=block.text[match.start():match.end()],
                    score=score,
                    page=block.page_number,
                    detection_layer="heuristic",
                    start=match.start(),
                    end=match.end(),
                ))
    return found


def filter_to_candidate_person_only(
    entities: list[PIIEntity],
    profile: CandidateProfile | None,
    header_name: PIIEntity | None,
) -> list[PIIEntity]:
    """Drop NER false positives (Naukri, school addresses, colleague names)."""
    filtered: list[PIIEntity] = []
    for entity in entities:
        if entity.entity_type != "PERSON":
            filtered.append(entity)
            continue

        if is_platform_name(entity.text):
            continue

        if header_name and entity.page == header_name.page and entity.start == header_name.start:
            filtered.append(entity)
            continue

        if profile and is_candidate_name(entity.text, profile):
            filtered.append(entity)

    return filtered
