import json
import logging
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from phantom.tools.registry import register_tool

_logger = logging.getLogger(__name__)

_notes_lock = threading.Lock()
_notes_storage: dict[str, dict[str, Any]] = {}
_notes_file: Path | None = None


def _get_notes_file() -> Path:
    """Return the path used for persistent notes (lazy-resolved)."""
    global _notes_file
    if _notes_file is None:
        # Try to find the current run directory from the global tracer
        try:
            from phantom.telemetry.tracer import get_global_tracer
            tracer = get_global_tracer()
            if tracer and hasattr(tracer, "run_dir") and tracer.run_dir:
                _notes_file = Path(tracer.run_dir) / "notes.json"
        except Exception:
            _logger.debug("Could not resolve run dir for notes", exc_info=True)
        if _notes_file is None:
            _notes_file = Path("phantom_runs") / "notes.json"
    return _notes_file


def _load_notes_from_disk() -> None:
    """Load persisted notes from disk into memory (called once at first access)."""
    global _notes_storage
    try:
        path = _get_notes_file()
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                _notes_storage.update(data)
                _logger.debug("Loaded %d notes from %s", len(data), path)
    except Exception as e:
        _logger.debug("Could not load notes from disk: %s", e)


def _persist_notes() -> None:
    """Persist current notes to disk (called after every mutation)."""
    try:
        path = _get_notes_file()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(_notes_storage, indent=2, default=str), encoding="utf-8")
    except Exception as e:
        _logger.debug("Could not persist notes to disk: %s", e)


# Load any existing notes on import
_load_notes_from_disk()


def _filter_notes(
    category: str | None = None,
    tags: list[str] | None = None,
    search_query: str | None = None,
) -> list[dict[str, Any]]:
    filtered_notes = []

    with _notes_lock:
        snapshot = list(_notes_storage.items())

    for note_id, note in snapshot:
        if category and note.get("category") != category:
            continue

        if tags:
            note_tags = note.get("tags", [])
            if not any(tag in note_tags for tag in tags):
                continue

        if search_query:
            search_lower = search_query.lower()
            title_match = search_lower in note.get("title", "").lower()
            content_match = search_lower in note.get("content", "").lower()
            if not (title_match or content_match):
                continue

        note_with_id = note.copy()
        note_with_id["note_id"] = note_id
        filtered_notes.append(note_with_id)

    filtered_notes.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return filtered_notes


@register_tool(sandbox_execution=False)
def create_note(
    title: str,
    content: str,
    category: str = "general",
    tags: list[str] | None = None,
) -> dict[str, Any]:
    try:
        if not title or not title.strip():
            return {"success": False, "error": "Title cannot be empty", "note_id": None}

        if not content or not content.strip():
            return {"success": False, "error": "Content cannot be empty", "note_id": None}

        valid_categories = ["general", "findings", "methodology", "questions", "plan"]
        # Map common LLM category aliases to valid categories
        category_aliases = {
            "vulnerability": "findings", "vuln": "findings", "vulnerabilities": "findings",
            "recon": "methodology", "reconnaissance": "methodology", "enumeration": "methodology",
            "scan": "methodology", "scanning": "methodology", "testing": "methodology",
            "exploit": "findings", "exploitation": "findings", "attack": "findings",
            "note": "general", "info": "general", "observation": "general",
            "todo": "plan", "task": "plan", "next": "plan", "action": "plan",
            "question": "questions", "query": "questions",
        }
        if category not in valid_categories:
            category = category_aliases.get(category.lower(), "general")

        note_id = str(uuid.uuid4())[:5]
        timestamp = datetime.now(UTC).isoformat()

        note = {
            "title": title.strip(),
            "content": content.strip(),
            "category": category,
            "tags": tags or [],
            "created_at": timestamp,
            "updated_at": timestamp,
        }

        with _notes_lock:
            _notes_storage[note_id] = note
            _persist_notes()

    except (ValueError, TypeError) as e:
        return {"success": False, "error": f"Failed to create note: {e}", "note_id": None}
    else:
        return {
            "success": True,
            "note_id": note_id,
            "message": f"Note '{title}' created successfully",
        }


@register_tool(sandbox_execution=False)
def list_notes(
    category: str | None = None,
    tags: list[str] | None = None,
    search: str | None = None,
) -> dict[str, Any]:
    try:
        filtered_notes = _filter_notes(category=category, tags=tags, search_query=search)

        return {
            "success": True,
            "notes": filtered_notes,
            "total_count": len(filtered_notes),
        }

    except (ValueError, TypeError) as e:
        return {
            "success": False,
            "error": f"Failed to list notes: {e}",
            "notes": [],
            "total_count": 0,
        }


@register_tool(sandbox_execution=False)
def update_note(
    note_id: str,
    title: str | None = None,
    content: str | None = None,
    tags: list[str] | None = None,
) -> dict[str, Any]:
    try:
        with _notes_lock:
            if note_id not in _notes_storage:
                return {"success": False, "error": f"Note with ID '{note_id}' not found"}

            note = _notes_storage[note_id]

            if title is not None:
                if not title.strip():
                    return {"success": False, "error": "Title cannot be empty"}
                note["title"] = title.strip()

            if content is not None:
                if not content.strip():
                    return {"success": False, "error": "Content cannot be empty"}
                note["content"] = content.strip()

            if tags is not None:
                note["tags"] = tags

            note["updated_at"] = datetime.now(UTC).isoformat()

            note_title = note["title"]
            _persist_notes()

        return {
            "success": True,
            "message": f"Note '{note_title}' updated successfully",
        }

    except (ValueError, TypeError) as e:
        return {"success": False, "error": f"Failed to update note: {e}"}


@register_tool(sandbox_execution=False)
def delete_note(note_id: str) -> dict[str, Any]:
    try:
        with _notes_lock:
            if note_id not in _notes_storage:
                return {"success": False, "error": f"Note with ID '{note_id}' not found"}

            note_title = _notes_storage[note_id]["title"]
            del _notes_storage[note_id]
            _persist_notes()

    except (ValueError, TypeError) as e:
        return {"success": False, "error": f"Failed to delete note: {e}"}
    else:
        return {
            "success": True,
            "message": f"Note '{note_title}' deleted successfully",
        }
