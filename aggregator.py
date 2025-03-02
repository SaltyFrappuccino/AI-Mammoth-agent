# aggregator.py
from agents.requirements_agent import RequirementsAgent
from agents.code_agent import CodeAgent
from agents.test_cases_agent import TestCasesAgent
from agents.documentation_agent import DocumentationAgent
from agents.final_report_agent import FinalReportAgent
from agents.analysis_evaluatora_agent import AnalysisEvaluatorAgent
from agents.compilance_evaluator import evaluate_code_compliance
from agents.bug_estimator_agent import BugEstimatorAgent, bug_estimator_schema


class Aggregator:
    def __init__(self, semantic_db=None):
        self.semantic_db = semantic_db
        self.requirements_agent = RequirementsAgent(semantic_db)
        self.code_agent = CodeAgent()
        self.test_cases_agent = TestCasesAgent()
        self.documentation_agent = DocumentationAgent(semantic_db)
        self.final_report_agent = FinalReportAgent()
        self.analysis_evaluator_agent = AnalysisEvaluatorAgent()
        self.bug_estimator_agent = BugEstimatorAgent()

    def aggregate(self, requirements_text: str, code_text: str, test_cases_text: str, documentation_text: str,
                  semantic_db=None) -> tuple:
        req_analysis = self.requirements_agent.call(requirements_text)
        code_analysis = self.code_agent.call(code_text)
        test_analysis = self.test_cases_agent.call(test_cases_text)
        doc_analysis = self.documentation_agent.call(documentation_text)

        agent_data = {
            "requirements_analysis": req_analysis,
            "code_analysis": code_analysis,
            "test_cases_analysis": test_analysis,
            "documentation_analysis": doc_analysis
        }

        compliance_result = evaluate_code_compliance(req_analysis, test_analysis, code_analysis)
        bug_estimation = self.bug_estimator_agent.estimate_bugs(requirements_text, code_analysis)
        
        # Передаем дополнительную информацию в final_report_agent
        agent_data["compliance_result"] = compliance_result
        agent_data["bug_estimation"] = bug_estimation
        
        final_report = self.final_report_agent.call(agent_data)

        if semantic_db is not None:
            from agents.semantic_agent import SemanticAgent
            semantic_agent = SemanticAgent(semantic_db)
            services = ["ServiceX", "ServiceY"]
            semantic_reports = []
            for service in services:
                report = semantic_agent.query_service(service)
                semantic_reports.append(report)
            semantic_info = "\n".join(semantic_reports)
            final_report += "\n\nДополнительная информация о сервисах:\n" + semantic_info

        evaluation = self.analysis_evaluator_agent.call(final_report)
        confidence_percentage = int(float(evaluation.split(':')[-1].strip().rstrip('%')) if '%' in evaluation else 80)
        
        # Формируем итоговый отчет по заданному шаблону
        template_report = f"""# Результаты анализа

*Story*: ссылка


- Соответствие кода требованиям: {compliance_result.get("code_to_requirements_percentage", 0)}%
- Соответствие тест кейсов требованиям: {compliance_result.get("tests_to_requirements_percentage", 0)}%
- Соответствие кода тест кейсам: {compliance_result.get("code_to_tests_percentage", 0)}%


## Общий список несоответствий:

{final_report}

## Итог:

- Потенциальное количество багов: {bug_estimation['bug_count']}
- Уверенность AI-агента в анализе: {confidence_percentage}%

## Объяснения по багам:

{bug_estimation['explanations']}
"""

        return template_report, bug_estimation
