# agents/final_report_agent.py
from langchain_core.messages import HumanMessage, SystemMessage
from config import llm


class FinalReportAgent:
    def __init__(self):
        self.system_prompt = (
            "Ты эксперт по системной интеграции. На основе представленных данных от агентов: анализа требований, анализа кода, тест-кейсов и документации, "
            "составь список несоответствий между требованиями, кодом и тестами. "
            "Для каждого несоответствия укажи следующее:\n\n"
            "Требование (текст из требований)\n\n"
            "*Проблема*: нет кода, нет теста, нет кода и теста\n"
            "*Объяснение*: текст объяснения\n\n"
            "Перечисли все несоответствия в таком формате. Не добавляй дополнительных заголовков или нумерацию."
        )

    def call(self, agent_data: dict) -> str:
        content = (
                "Анализ требований:\n" + agent_data.get("requirements_analysis", "") + "\n\n" +
                "Анализ кода:\n" + agent_data.get("code_analysis", "") + "\n\n" +
                "Анализ тест-кейсов:\n" + agent_data.get("test_cases_analysis", "") + "\n\n" +
                "Анализ документации:\n" + agent_data.get("documentation_analysis", "") + "\n\n" +
                "Результаты проверки соответствия:\n" + str(agent_data.get("compliance_result", {})) + "\n\n" +
                "Оценка багов:\n" + str(agent_data.get("bug_estimation", {}))
        )
        
        messages = [
            SystemMessage(content=self.system_prompt),
            HumanMessage(content=content)
        ]
        response = llm.invoke(messages, function_call="none")
        return response.content
