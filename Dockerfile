FROM python:3.9-bullseye

WORKDIR /app

COPY requirements.txt .

RUN pip install urllib3 --upgrade

RUN pip install --no-cache-dir --trusted-host pypi.org --trusted-host files.pythonhosted.org --trusted-host pypi.python.org -r requirements.txt

COPY . .

RUN mkdir -p output/visualizations output/reports

EXPOSE 8080

CMD ["python", "-m", "main"] 