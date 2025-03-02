import React, { useState } from 'react';
import styled from 'styled-components';
import { motion } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
import { FiUpload, FiCode, FiFileText, FiCheckCircle, FiAlertTriangle } from 'react-icons/fi';
import axios from 'axios';

// Импорт компонентов
import Button from '../components/Button';
import Input from '../components/Input';
import Card from '../components/Card';
import Loader from '../components/Loader';

// Стилизованные компоненты
const PageContainer = styled.div`
  max-width: 1200px;
  margin: 0 auto;
  padding: var(--spacing-lg);
`;

const PageHeader = styled.div`
  margin-bottom: var(--spacing-xl);
  text-align: center;
`;

const Title = styled.h1`
  font-size: var(--font-size-xxl);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-md);
`;

const Subtitle = styled.p`
  font-size: var(--font-size-lg);
  color: var(--color-text-secondary);
  max-width: 800px;
  margin: 0 auto;
`;

const FormContainer = styled(Card)`
  max-width: 800px;
  margin: 0 auto;
  margin-bottom: var(--spacing-xl);
`;

const FormSection = styled.div`
  margin-bottom: var(--spacing-lg);
`;

const SectionTitle = styled.h2`
  font-size: var(--font-size-lg);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-md);
  display: flex;
  align-items: center;
  
  svg {
    margin-right: var(--spacing-sm);
    color: var(--color-primary);
  }
`;

const TextArea = styled.textarea`
  width: 100%;
  min-height: 200px;
  padding: var(--spacing-md);
  border: 1px solid var(--color-neutral-light);
  border-radius: var(--border-radius-md);
  font-family: 'SB Sans Display', monospace;
  font-size: var(--font-size-md);
  resize: vertical;
  background-color: var(--color-white);
  transition: border-color 0.2s ease;
  
  &:focus {
    outline: none;
    border-color: var(--color-primary);
    box-shadow: 0 0 0 3px var(--color-primary-light);
  }
`;

const UploadButton = styled.div`
  display: flex;
  align-items: center;
  margin-top: var(--spacing-md);
  
  input[type="file"] {
    display: none;
  }
`;

const FileName = styled.span`
  margin-left: var(--spacing-md);
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
`;

const FormActions = styled.div`
  display: flex;
  justify-content: space-between;
  margin-top: var(--spacing-xl);
  
  @media (max-width: 600px) {
    flex-direction: column;
    gap: var(--spacing-md);
  }
`;

const InfoCard = styled(Card)`
  margin-bottom: var(--spacing-lg);
  display: flex;
  align-items: center;
  
  svg {
    font-size: 24px;
    margin-right: var(--spacing-md);
  }
`;

const SuccessIcon = styled(FiCheckCircle)`
  color: var(--color-success);
`;

const WarningIcon = styled(FiAlertTriangle)`
  color: var(--color-warning);
`;

// Анимационные варианты
const fadeIn = {
  hidden: { opacity: 0, y: 20 },
  visible: { 
    opacity: 1, 
    y: 0,
    transition: { duration: 0.6 }
  }
};

// Компонент страницы анализа
const AnalyzePage = () => {
  const navigate = useNavigate();
  
  // Состояния
  const [code, setCode] = useState('');
  const [requirements, setRequirements] = useState('');
  const [testCases, setTestCases] = useState('');
  const [documentation, setDocumentation] = useState('');
  const [codeFileName, setCodeFileName] = useState('');
  const [requirementsFileName, setRequirementsFileName] = useState('');
  const [testCasesFileName, setTestCasesFileName] = useState('');
  const [documentationFileName, setDocumentationFileName] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  
  // Обработчики загрузки файлов
  const handleCodeFileChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      setCodeFileName(file.name);
      const reader = new FileReader();
      reader.onload = (event) => {
        setCode(event.target.result);
      };
      reader.readAsText(file);
    }
  };
  
  const handleRequirementsFileChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      setRequirementsFileName(file.name);
      const reader = new FileReader();
      reader.onload = (event) => {
        setRequirements(event.target.result);
      };
      reader.readAsText(file);
    }
  };
  
  const handleTestCasesFileChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      setTestCasesFileName(file.name);
      const reader = new FileReader();
      reader.onload = (event) => {
        setTestCases(event.target.result);
      };
      reader.readAsText(file);
    }
  };
  
  const handleDocumentationFileChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      setDocumentationFileName(file.name);
      const reader = new FileReader();
      reader.onload = (event) => {
        setDocumentation(event.target.result);
      };
      reader.readAsText(file);
    }
  };
  
  // Обработчик отправки формы
  const handleSubmit = async (e) => {
    e.preventDefault();
    
    // Проверка обязательных полей
    if (!code.trim()) {
      setError('Необходимо указать код для анализа');
      return;
    }
    
    try {
      setIsLoading(true);
      setError(null);
      
      // Отправка данных на API
      const response = await axios.post('/analyze', {
        code,
        requirements,
        test_cases: testCases,
        documentation,
        semantic_db: {},
        analyze_security: true
      });
      
      // Сохранение результата анализа и редирект на страницу результатов
      localStorage.setItem('analysisResult', JSON.stringify(response.data));
      navigate('/results');
      
    } catch (err) {
      console.error('Ошибка при отправке данных на анализ:', err);
      setError(err.response?.data?.message || 'Произошла ошибка при анализе кода. Пожалуйста, попробуйте снова.');
    } finally {
      setIsLoading(false);
    }
  };
  
  // Очистка формы
  const handleReset = () => {
    setCode('');
    setRequirements('');
    setTestCases('');
    setDocumentation('');
    setCodeFileName('');
    setRequirementsFileName('');
    setTestCasesFileName('');
    setDocumentationFileName('');
    setError(null);
  };
  
  return (
    <PageContainer>
      {isLoading && <Loader overlay={true} text="Анализ кода..." />}
      
      <motion.div 
        initial="hidden"
        animate="visible"
        variants={fadeIn}
      >
        <PageHeader>
          <Title>Анализ кода</Title>
          <Subtitle>
            Загрузите ваш код, требования и тесты для полного анализа с использованием AI-Mammoth.
            Система проведет проверку кода, выявит потенциальные проблемы и предложит оптимизации.
          </Subtitle>
        </PageHeader>
        
        {error && (
          <InfoCard variant="bordered">
            <WarningIcon />
            <p>{error}</p>
          </InfoCard>
        )}
        
        <FormContainer variant="sber">
          <form onSubmit={handleSubmit}>
            <FormSection>
              <SectionTitle>
                <FiCode /> Код для анализа
              </SectionTitle>
              <TextArea
                placeholder="Вставьте ваш код или загрузите файл..."
                value={code}
                onChange={(e) => setCode(e.target.value)}
              />
              <UploadButton>
                <label htmlFor="code-upload">
                  <Button variant="outlined" as="span">
                    <FiUpload /> Загрузить файл
                  </Button>
                </label>
                <input
                  id="code-upload"
                  type="file"
                  accept=".py,.js,.java,.c,.cpp,.cs,.go,.rb,.php,.ts,.html,.css"
                  onChange={handleCodeFileChange}
                />
                {codeFileName && <FileName>{codeFileName}</FileName>}
              </UploadButton>
            </FormSection>
            
            <FormSection>
              <SectionTitle>
                <FiFileText /> Требования
              </SectionTitle>
              <TextArea
                placeholder="Вставьте требования к коду или загрузите файл..."
                value={requirements}
                onChange={(e) => setRequirements(e.target.value)}
              />
              <UploadButton>
                <label htmlFor="requirements-upload">
                  <Button variant="outlined" as="span">
                    <FiUpload /> Загрузить файл
                  </Button>
                </label>
                <input
                  id="requirements-upload"
                  type="file"
                  accept=".txt,.md,.pdf,.doc,.docx"
                  onChange={handleRequirementsFileChange}
                />
                {requirementsFileName && <FileName>{requirementsFileName}</FileName>}
              </UploadButton>
            </FormSection>
            
            <FormSection>
              <SectionTitle>
                <FiFileText /> Тесты 
              </SectionTitle>
              <TextArea
                placeholder="Вставьте тесты или загрузите файл..."
                value={testCases}
                onChange={(e) => setTestCases(e.target.value)}
              />
              <UploadButton>
                <label htmlFor="tests-upload">
                  <Button variant="outlined" as="span">
                    <FiUpload /> Загрузить файл
                  </Button>
                </label>
                <input
                  id="tests-upload"
                  type="file"
                  accept=".py,.js,.java,.c,.cpp,.cs,.go,.rb,.php,.ts"
                  onChange={handleTestCasesFileChange}
                />
                {testCasesFileName && <FileName>{testCasesFileName}</FileName>}
              </UploadButton>
            </FormSection>
            
            <FormSection>
              <SectionTitle>
                <FiFileText /> Документация 
              </SectionTitle>
              <TextArea
                placeholder="Вставьте документацию или загрузите файл..."
                value={documentation}
                onChange={(e) => setDocumentation(e.target.value)}
              />
              <UploadButton>
                <label htmlFor="documentation-upload">
                  <Button variant="outlined" as="span">
                    <FiUpload /> Загрузить файл
                  </Button>
                </label>
                <input
                  id="documentation-upload"
                  type="file"
                  accept=".txt,.md,.pdf,.doc,.docx"
                  onChange={handleDocumentationFileChange}
                />
                {documentationFileName && <FileName>{documentationFileName}</FileName>}
              </UploadButton>
            </FormSection>
            
            <FormActions>
              <Button type="button" variant="outlined" onClick={handleReset}>
                Очистить
              </Button>
              <Button type="submit" variant="gradient">
                Начать анализ
              </Button>
            </FormActions>
          </form>
        </FormContainer>
        
        <InfoCard variant="gradient">
          <SuccessIcon />
          <div>
            <h3>Как это работает?</h3>
            <p>AI-Mammoth анализирует ваш код с помощью алгоритмов машинного обучения. Чем больше информации вы предоставите (требования, тесты), тем более детальный анализ будет проведен.</p>
          </div>
        </InfoCard>
      </motion.div>
    </PageContainer>
  );
};

export default AnalyzePage; 