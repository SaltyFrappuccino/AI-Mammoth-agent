import tkinter as tk
from tkinter import scrolledtext, messagebox
import requests
import json

def create_labeled_text(master, label_text, initial_text="", height=5):
    frame = tk.Frame(master)
    label = tk.Label(frame, text=label_text)
    label.pack(anchor="w")
    text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, height=height)
    text.pack(fill="both", expand=True)
    text.insert(tk.END, initial_text) 
    frame.pack(fill="both", expand=True, padx=10, pady=5)
    return text

def run_analysis():
    requirements = requirements_text.get("1.0", tk.END).strip()
    code = code_text.get("1.0", tk.END).strip()
    test_cases = test_cases_text.get("1.0", tk.END).strip()
    documentation = documentation_text.get("1.0", tk.END).strip()
    
    try:
        semantic_db = json.loads(semantic_db_text.get("1.0", tk.END).strip())
    except json.JSONDecodeError:
        messagebox.showerror("Ошибка", "Неверный формат JSON для семантической базы")
        return

    if not requirements or not code or not test_cases:
        messagebox.showwarning("Предупреждение", "Пожалуйста, заполните все обязательные поля.")
        return

    api_url = "http://localhost:8080/analyze"  

    payload = {
        "requirements": requirements,
        "code": code,
        "test_cases": test_cases,
        "documentation": documentation,
        "semantic_db": semantic_db
    }

    try:
        response = requests.post(api_url, json=payload)
        response.raise_for_status()
        result = response.json().get("final_report", "Нет данных в ответе.")
        bugs = response.json().get("bugs", "N/A")
    except requests.exceptions.RequestException as e:
        result = f"Ошибка при отправке запроса: {str(e)}"
        bugs = "N/A"
    except ValueError:
        result = f"Ошибка парсинга ответа: {response.text}"
        bugs = "N/A"

    result_window = tk.Toplevel(root)
    result_window.title("Результат анализа")
    
    bugs_label = tk.Label(result_window, text=f"Прогнозируемое количество багов: {bugs}")
    bugs_label.pack(pady=5)
    
    result_text = scrolledtext.ScrolledText(result_window, wrap=tk.WORD)
    result_text.pack(fill="both", expand=True, padx=10, pady=5)
    result_text.insert(tk.END, result)
    result_text.configure(state="disabled")

root = tk.Tk()
root.title("AI-Ассистент для анализа кода")
root.geometry("1000x800")

requirements_text = create_labeled_text(root, "Требования:", "Введите требования здесь...")
code_text = create_labeled_text(root, "Код:", "Вставьте код сюда...")
test_cases_text = create_labeled_text(root, "Тест-кейсы:", "Опишите тест-кейсы...")
documentation_text = create_labeled_text(root, "Документация:", "Добавьте документацию...")
semantic_db_text = create_labeled_text(root, "Семантическая база (JSON):", '{\n    "documents": []\n}', height=3)

analyze_button = tk.Button(root, text="Запустить анализ", command=run_analysis)
analyze_button.pack(pady=10)

root.mainloop()