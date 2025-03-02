# agents/compliance_evaluator.py
from langchain_core.messages import HumanMessage, SystemMessage
from config import llm


def evaluate_code_compliance(requirements_analysis: str, test_cases_analysis: str, code_analysis: str) -> dict:
    """
    Используя GigaChat, оценивает процент соответствия кода требованиям и тест-кейсам.
    Функция принимает текст анализа требований, тест-кейсов и кода, объединяет их,
    и отправляет в модель. Модель должна вернуть целое число от 0 до 100, где 0 — полное несоответствие,
    а 100 — полное соответствие.
    """
    analysis_text = (
            "Анализ требований:\n" + requirements_analysis + "\n\n" +
            "Анализ тест-кейсов:\n" + test_cases_analysis + "\n\n" +
            "Анализ кода:\n" + code_analysis + "\n\n" +
            "На основе этого анализа, оцени, насколько код соответствует требованиям и тест-кейсам, "
            "и выдай результат в виде целого числа от 0 до 100."
    )

    system_prompt = (
        "Ты эксперт по оценке соответствия кода требованиям. На основе предоставленного анализа дай оценку "
        "соответствия в процентах (от 0 до 100)."
    )

    messages = [
        SystemMessage(content=system_prompt),
        HumanMessage(content=analysis_text)
    ]

    response = llm.invoke(messages, function_call="none")

    try:
        result_text = response.content.strip()
        digits = ''.join(filter(str.isdigit, result_text))
        compliance_percentage = int(digits) if digits else 0
    except Exception:
        compliance_percentage = 0

    return {"compliance_percentage": compliance_percentage}


evaluate_code_compliance_schema = {
    "name": "evaluate_code_compliance",
    "description": "Используя GigaChat, оценивает процент соответствия кода требованиям и тест-кейсам, на основе предоставленного текста анализа.",
    "parameters": {
        "type": "object",
        "properties": {
            "requirements_analysis": {
                "type": "string",
                "description": "Анализ соответствия кода требованиям."
            },
            "test_cases_analysis": {
                "type": "string",
                "description": "Анализ прохождения тест-кейсов."
            },
            "code_analysis": {
                "type": "string",
                "description": "Анализ кода на соответствие требованиям."
            }
        },
        "required": [
            "requirements_analysis",
            "test_cases_analysis",
            "code_analysis"
        ]
    },
    "return_parameters": {
        "type": "object",
        "properties": {
            "compliance_percentage": {
                "type": "number",
                "description": "Процент соответствия кода требованиям и тест-кейсам (от 0 до 100)."
            }
        },
        "required": ["compliance_percentage"]
    }
}
