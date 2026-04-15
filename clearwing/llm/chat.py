from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

from clearwing.agent.tooling import as_native_tool_spec
from clearwing.llm.native import AsyncLLMClient, NativeMessage, NativeToolCall, NativeToolSpec


def extract_text_content(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
                continue
            if not isinstance(item, dict):
                continue
            item_type = item.get("type")
            if item_type in {"text", "text-plain"}:
                text = item.get("text")
                if isinstance(text, str) and text:
                    parts.append(text)
            elif item_type == "reasoning":
                reasoning = item.get("reasoning")
                if isinstance(reasoning, str) and reasoning:
                    parts.append(reasoning)
        return "\n".join(part for part in parts if part)
    return str(content)


@dataclass(slots=True)
class BaseMessage:
    content: Any
    name: str | None = None
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    tool_call_id: str | None = None
    response_metadata: dict[str, Any] = field(default_factory=dict)
    type: str = field(init=False, default="base")

    @property
    def text(self) -> str:
        return extract_text_content(self.content)


@dataclass(slots=True)
class HumanMessage(BaseMessage):
    type: str = field(init=False, default="human")


@dataclass(slots=True)
class SystemMessage(BaseMessage):
    type: str = field(init=False, default="system")


@dataclass(slots=True)
class AIMessage(BaseMessage):
    type: str = field(init=False, default="ai")


@dataclass(slots=True)
class ToolMessage(BaseMessage):
    type: str = field(init=False, default="tool")


def _message_to_native(message: Any) -> tuple[str | None, NativeMessage | None]:
    if isinstance(message, str):
        return None, NativeMessage(role="user", content=message)

    if isinstance(message, NativeMessage):
        if message.role == "system":
            return message.content, None
        return None, message

    if isinstance(message, dict):
        role = str(message.get("role", "user"))
        content = extract_text_content(message.get("content", ""))
        if role == "system":
            return content, None
        if role == "tool":
            return None, NativeMessage(
                role="tool",
                content=content,
                tool_response_call_id=message.get("tool_call_id"),
            )
        tool_calls = _normalize_tool_calls(message.get("tool_calls", []))
        return None, NativeMessage(role=role, content=content, tool_calls=tool_calls)

    if isinstance(message, BaseMessage):
        if message.type == "system":
            return message.text, None
        if message.type == "tool":
            return None, NativeMessage(
                role="tool",
                content=message.text,
                tool_response_call_id=message.tool_call_id,
            )
        role = "assistant" if message.type == "ai" else "user"
        return None, NativeMessage(
            role=role,
            content=message.text,
            tool_calls=_normalize_tool_calls(message.tool_calls),
        )

    role = getattr(message, "type", "user")
    content = extract_text_content(getattr(message, "content", message))
    if role == "system":
        return content, None
    if role == "tool":
        return None, NativeMessage(
            role="tool",
            content=content,
            tool_response_call_id=getattr(message, "tool_call_id", None),
        )
    tool_calls = _normalize_tool_calls(getattr(message, "tool_calls", []))
    return None, NativeMessage(
        role="assistant" if role == "ai" else "user",
        content=content,
        tool_calls=tool_calls,
    )


def _normalize_tool_calls(tool_calls: Iterable[Any]) -> list[NativeToolCall]:
    normalized: list[NativeToolCall] = []
    for tool_call in tool_calls:
        if isinstance(tool_call, NativeToolCall):
            normalized.append(tool_call)
            continue
        if isinstance(tool_call, dict):
            args = tool_call.get("args") or {}
            normalized.append(
                NativeToolCall(
                    id=str(tool_call.get("id") or ""),
                    name=str(tool_call.get("name") or ""),
                    arguments=args if isinstance(args, dict) else {},
                    arguments_json=json.dumps(args if isinstance(args, dict) else {}),
                )
            )
    return normalized


def _coerce_native_messages(messages: Any) -> tuple[str | None, list[NativeMessage]]:
    if isinstance(messages, (str, BaseMessage, NativeMessage, dict)):
        messages = [messages]

    system_parts: list[str] = []
    native_messages: list[NativeMessage] = []
    for message in messages or []:
        system_text, native_message = _message_to_native(message)
        if system_text:
            system_parts.append(system_text)
        if native_message is not None:
            native_messages.append(native_message)

    system = "\n\n".join(part for part in system_parts if part).strip() or None
    return system, native_messages


class ChatModel:
    def __init__(
        self,
        *,
        model_name: str,
        api_key: str,
        provider_name: str,
        base_url: str | None = None,
        default_system: str = "You are a helpful assistant.",
        bound_tools: Sequence[NativeToolSpec] | None = None,
        tool_choice: str | None = None,
    ) -> None:
        self.model_name = model_name
        self.api_key = api_key
        self.provider_name = provider_name
        self.base_url = base_url
        self.default_system = default_system
        self.bound_tools = list(bound_tools or [])
        self.tool_choice = tool_choice
        self._client = AsyncLLMClient(
            model_name=model_name,
            api_key=api_key,
            provider_name=provider_name,
            base_url=base_url,
            default_system=default_system,
        )

    @property
    def client(self) -> AsyncLLMClient:
        return self._client

    def bind_tools(
        self,
        tools: Sequence[Any],
        *,
        tool_choice: str | None = None,
        **_: Any,
    ) -> ChatModel:
        native_tools = [as_native_tool_spec(tool) for tool in tools]
        return ChatModel(
            model_name=self.model_name,
            api_key=self.api_key,
            provider_name=self.provider_name,
            base_url=self.base_url,
            default_system=self.default_system,
            bound_tools=native_tools,
            tool_choice=tool_choice or self.tool_choice,
        )

    def invoke(self, messages: Any) -> AIMessage:
        system, native_messages = _coerce_native_messages(messages)
        response = self._client.chat(
            messages=native_messages,
            system=system or self.default_system,
            tools=self.bound_tools or None,
        )
        return AIMessage(
            content=response.text,
            tool_calls=[
                {
                    "id": tool_call.id,
                    "name": tool_call.name,
                    "args": tool_call.arguments,
                    "type": "tool_call",
                }
                for tool_call in response.tool_calls
            ],
            response_metadata={
                "usage": {
                    "input_tokens": response.usage.input_tokens,
                    "output_tokens": response.usage.output_tokens,
                    "total_tokens": response.usage.total_tokens,
                },
                "model": response.model or self.model_name,
            },
        )

    async def ainvoke(self, messages: Any) -> AIMessage:
        system, native_messages = _coerce_native_messages(messages)
        response = await self._client.achat(
            messages=native_messages,
            system=system or self.default_system,
            tools=self.bound_tools or None,
        )
        return AIMessage(
            content=response.text,
            tool_calls=[
                {
                    "id": tool_call.id,
                    "name": tool_call.name,
                    "args": tool_call.arguments,
                    "type": "tool_call",
                }
                for tool_call in response.tool_calls
            ],
            response_metadata={
                "usage": {
                    "input_tokens": response.usage.input_tokens,
                    "output_tokens": response.usage.output_tokens,
                    "total_tokens": response.usage.total_tokens,
                },
                "model": response.model or self.model_name,
            },
        )
