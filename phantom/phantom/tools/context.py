from contextvars import ContextVar
from contextvars import Token


current_agent_id: ContextVar[str] = ContextVar("current_agent_id", default="default")


def get_current_agent_id() -> str:
    return current_agent_id.get()


def set_current_agent_id(agent_id: str) -> Token[str]:
    return current_agent_id.set(agent_id)


def reset_current_agent_id(token: Token[str]) -> None:
    current_agent_id.reset(token)
