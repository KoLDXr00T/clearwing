import importlib


def create_agent(*args, **kwargs):
    return importlib.import_module("clearwing.agent.graph").create_agent(*args, **kwargs)


def __getattr__(name):
    if name == "AgentState":
        return importlib.import_module("clearwing.agent.state").AgentState
    raise AttributeError(name)


__all__ = ["AgentState", "create_agent"]
