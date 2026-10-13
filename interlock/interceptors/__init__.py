from . import crewai, google_adk, litellm, openai
from .decorator import guard, monitor
from .langchain import guard_langchain_tools
from .mcp import enforce_tool_call, guard_mcp_session
from .openai import guard_tool_loop

# The framework adapters all expose the same ``guard_tool_loop`` symbol, so a
# caller reaching for one framework names its module. These aliases give the
# other three a distinct, discoverable name at the package root.
guard_litellm_tool_loop = litellm.guard_tool_loop
guard_crewai_tool_loop = crewai.guard_tool_loop
guard_adk_tool_loop = google_adk.guard_tool_loop

#: Every shipped framework adapter module, in doctor's reporting order. Each
#: exposes ``FRAMEWORK``, ``MODULE``, ``SURFACE`` and ``framework_available()``;
#: ``interlock doctor`` reads them to name the detected frameworks and the
#: surfaces left uncovered.
FRAMEWORK_ADAPTERS = (openai, litellm, crewai, google_adk)

__all__ = [
    "guard",
    "monitor",
    "guard_mcp_session",
    "enforce_tool_call",
    "guard_langchain_tools",
    "guard_tool_loop",
    "guard_litellm_tool_loop",
    "guard_crewai_tool_loop",
    "guard_adk_tool_loop",
    "FRAMEWORK_ADAPTERS",
]
