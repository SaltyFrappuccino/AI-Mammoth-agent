# agents/code_agent.py
from agents.base_agent import BaseAgent

class CodeAgent(BaseAgent):
    def __init__(self):
        system_prompt = (
            "Ты профессиональный разработчик и код-ревьюер. Проанализируй предоставленный код и сравни его с требованиями задачи. "
            "Определи, какие части кода реализуют требования, укажи файлы и строки, где реализован функционал, а также отметь, если требование выполнено частично или не выполнено."
        )
        super().__init__("CodeAgent", system_prompt)
