# agents/test_cases_agent.py
from agents.base_agent import BaseAgent

class TestCasesAgent(BaseAgent):
    def __init__(self):
        system_prompt = (
            "Ты опытный тестировщик. Проанализируй предоставленные тест-кейсы и определи, какие из них подтверждают корректную реализацию функционала. "
            "Верни краткий отчёт о прохождении тестов и выявленных проблемах."
        )
        super().__init__("TestCasesAgent", system_prompt)
