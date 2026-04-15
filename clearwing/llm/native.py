from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Any


def _run_coro_sync(coro):
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    raise RuntimeError("Synchronous wrapper called from a running event loop")


@dataclass(slots=True)
class NativeToolCall:
    id: str
    name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    arguments_json: str = "{}"


@dataclass(slots=True)
class NativeToolSpec:
    name: str
    description: str
    schema: dict[str, Any]
    handler: Any

    async def ainvoke(self, arguments: dict[str, Any]) -> Any:
        if asyncio.iscoroutinefunction(self.handler):
            return await self.handler(**arguments)
        return await asyncio.to_thread(self.handler, **arguments)


@dataclass(slots=True)
class NativeMessage:
    role: str
    content: str = ""
    tool_calls: list[NativeToolCall] = field(default_factory=list)
    tool_response_call_id: str | None = None


@dataclass(slots=True)
class NativeUsage:
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0


@dataclass(slots=True)
class NativeResponse:
    text: str = ""
    tool_calls: list[NativeToolCall] = field(default_factory=list)
    usage: NativeUsage = field(default_factory=NativeUsage)
    model: str = ""


class AsyncLLMClient:
    """Native async wrapper around genai-pyo3 for sourcehunt/runtime use.

    This intentionally bypasses LangChain's message/result model and exposes
    only the pieces Clearwing actually needs: text, tool calls, usage, and
    bounded concurrency.
    """

    def __init__(
        self,
        *,
        model_name: str,
        provider_name: str,
        api_key: str,
        base_url: str | None = None,
        max_concurrency: int = 4,
        default_system: str = "You are a helpful assistant.",
    ) -> None:
        self.model_name = model_name
        self.provider_name = provider_name
        self.api_key = api_key
        self.base_url = base_url
        self.default_system = default_system
        self._semaphore = asyncio.Semaphore(max(1, max_concurrency))

    async def achat(
        self,
        *,
        messages: list[NativeMessage],
        system: str | None = None,
        tools: list[NativeToolSpec] | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> NativeResponse:
        try:
            from genai_pyo3 import ChatMessage, ChatOptions, ChatRequest, Client, Tool, ToolCall
        except ImportError as exc:  # pragma: no cover - dependency issue
            raise ImportError("genai-pyo3 is required for native async LLM calls") from exc

        request_messages: list[Any] = []
        for message in messages:
            if message.role == "assistant" and message.tool_calls:
                request_messages.append(
                    ChatMessage(
                        "assistant",
                        message.content,
                        tool_calls=[
                            ToolCall(
                                call_id=tc.id,
                                fn_name=tc.name,
                                fn_arguments_json=tc.arguments_json,
                            )
                            for tc in message.tool_calls
                        ],
                    )
                )
            elif message.role == "tool":
                request_messages.append(
                    ChatMessage(
                        "tool",
                        message.content,
                        tool_response_call_id=message.tool_response_call_id,
                    )
                )
            else:
                request_messages.append(ChatMessage(message.role, message.content))

        request_tools = None
        if tools:
            request_tools = [
                Tool(
                    tool.name,
                    tool.description,
                    json.dumps(tool.schema),
                )
                for tool in tools
            ]

        request = ChatRequest(
            messages=request_messages,
            system=system or self.default_system,
            tools=request_tools,
        )
        options = ChatOptions(
            temperature=temperature,
            max_tokens=max_tokens,
            capture_content=True,
            capture_usage=True,
            capture_tool_calls=True,
        )

        async with self._semaphore:
            client = self._build_client(Client)
            response = await client.achat(self.model_name, request, options)

        tool_calls: list[NativeToolCall] = []
        for tool_call in response.tool_calls or []:
            args = _safe_json_loads(tool_call.fn_arguments_json)
            tool_calls.append(
                NativeToolCall(
                    id=tool_call.call_id,
                    name=tool_call.fn_name,
                    arguments=args if isinstance(args, dict) else {},
                    arguments_json=tool_call.fn_arguments_json or "{}",
                )
            )

        usage = NativeUsage(
            input_tokens=response.usage.prompt_tokens or 0,
            output_tokens=response.usage.completion_tokens or 0,
            total_tokens=response.usage.total_tokens or 0,
        )

        text = response.text or ""
        if not text and response.texts:
            text = "\n".join(t for t in response.texts if t)

        return NativeResponse(
            text=text,
            tool_calls=tool_calls,
            usage=usage,
            model=response.provider_model_name or self.model_name,
        )

    def chat(self, **kwargs: Any) -> NativeResponse:
        return _run_coro_sync(self.achat(**kwargs))

    async def aask_text(
        self,
        *,
        system: str,
        user: str,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> NativeResponse:
        return await self.achat(
            messages=[NativeMessage(role="user", content=user)],
            system=system,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    async def aask_json(
        self,
        *,
        system: str,
        user: str,
        expect: str = "object",
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> tuple[Any, NativeResponse]:
        response = await self.aask_text(
            system=system,
            user=user,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        if expect == "array":
            return extract_json_array(response.text), response
        return extract_json_object(response.text), response

    def _build_client(self, client_cls):
        base_url = self.base_url
        if base_url:
            base_url = base_url if base_url.endswith("/") else f"{base_url}/"
            if self.api_key:
                return client_cls.with_api_key_and_base_url(
                    self.provider_name,
                    self.api_key,
                    base_url,
                )
            return client_cls.with_base_url(self.provider_name, base_url)
        if self.api_key:
            return client_cls.with_api_key(self.provider_name, self.api_key)
        return client_cls()


def extract_json_object(text: str) -> dict[str, Any]:
    match = re.search(r"\{[\s\S]*\}", text)
    if not match:
        raise ValueError("response did not contain a JSON object")
    parsed = json.loads(match.group(0))
    if not isinstance(parsed, dict):
        raise ValueError("response JSON was not an object")
    return parsed


def extract_json_array(text: str) -> list[Any]:
    match = re.search(r"\[[\s\S]*\]", text)
    if not match:
        raise ValueError("response did not contain a JSON array")
    parsed = json.loads(match.group(0))
    if not isinstance(parsed, list):
        raise ValueError("response JSON was not an array")
    return parsed


def _safe_json_loads(value: str) -> Any:
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return {}
