# agents/base_agent.py
from langchain_core.messages import HumanMessage, SystemMessage
from config import llm


class BaseAgent:
    def __init__(self, name: str, system_prompt: str):
        self.name = name
        self.system_prompt = system_prompt

    def call(self, input_text: str) -> str:
        messages = [
            SystemMessage(content=self.system_prompt),
            HumanMessage(content=input_text)
        ]
        response = llm.invoke(messages)
        return response.content
