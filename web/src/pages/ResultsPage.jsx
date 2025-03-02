import React, { useState, useEffect } from 'react';
import styled from 'styled-components';
import { motion } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
import { FiAlertCircle, FiCheckCircle, FiInfo, FiDownload, FiBarChart2 } from 'react-icons/fi';
import ReactMarkdown from 'react-markdown';
import SyntaxHighlighter from 'react-syntax-highlighter';
import { docco } from 'react-syntax-highlighter/dist/esm/styles/hljs';

// Components
import Button from '../components/Button';
import Card from '../components/Card';

// Styled Components
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

const ResultsContainer = styled(Card)`
  margin-bottom: var(--spacing-xl);
`;

const ResultsHeader = styled.div`
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-lg);
  padding-bottom: var(--spacing-md);
  border-bottom: 1px solid var(--color-neutral-light);
  
  @media (max-width: 768px) {
    flex-direction: column;
    align-items: flex-start;
    gap: var(--spacing-md);
  }
`;

const ResultsTitle = styled.h2`
  font-size: var(--font-size-xl);
  color: var(--color-text-primary);
  display: flex;
  align-items: center;
  
  svg {
    margin-right: var(--spacing-sm);
    color: var(--color-primary);
  }
`;

const ResultsActions = styled.div`
  display: flex;
  gap: var(--spacing-md);
  
  @media (max-width: 600px) {
    flex-direction: column;
    width: 100%;
  }
`;

const ResultsContent = styled.div`
  h1, h2, h3, h4, h5, h6 {
    color: var(--color-text-primary);
    margin-top: var(--spacing-lg);
    margin-bottom: var(--spacing-md);
  }
  
  p {
    margin-bottom: var(--spacing-md);
    line-height: 1.6;
  }
  
  ul, ol {
    margin-bottom: var(--spacing-md);
    padding-left: var(--spacing-lg);
  }
  
  li {
    margin-bottom: var(--spacing-sm);
  }
  
  code {
    background-color: var(--color-neutral-light);
    padding: 2px 4px;
    border-radius: var(--border-radius-sm);
    font-family: monospace;
  }
  
  pre {
    background-color: #f5f5f5;
    padding: var(--spacing-md);
    border-radius: var(--border-radius-md);
    overflow-x: auto;
    margin-bottom: var(--spacing-md);
  }
  
  blockquote {
    border-left: 4px solid var(--color-primary);
    padding-left: var(--spacing-md);
    color: var(--color-text-secondary);
    font-style: italic;
    margin-bottom: var(--spacing-md);
  }
`;

const StatsContainer = styled.div`
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: var(--spacing-md);
  margin-bottom: var(--spacing-lg);
`;

const StatCard = styled(Card)`
  padding: var(--spacing-md);
  text-align: center;
  
  h3 {
    font-size: var(--font-size-md);
    color: var(--color-text-secondary);
    margin-bottom: var(--spacing-sm);
  }
  
  .value {
    font-size: var(--font-size-xl);
    font-weight: 600;
    color: ${props => props.color || 'var(--color-primary)'};
  }
`;

const BugsList = styled.div`
  margin-top: var(--spacing-lg);
`;

const BugItem = styled.div`
  background-color: var(--color-neutral-ultralight);
  border-radius: var(--border-radius-md);
  padding: var(--spacing-md);
  margin-bottom: var(--spacing-md);
  border-left: 4px solid ${props => {
    switch(props.severity) {
      case 'critical': return 'var(--color-error)';
      case 'high': return 'var(--color-warning)';
      case 'medium': return 'var(--color-warning-light)';
      case 'low': return 'var(--color-info)';
      default: return 'var(--color-neutral)';
    }
  }};
  
  h4 {
    display: flex;
    align-items: center;
    margin-bottom: var(--spacing-sm);
    
    svg {
      margin-right: var(--spacing-sm);
    }
  }
  
  .location {
    font-family: monospace;
    background-color: var(--color-neutral-light);
    padding: 2px 6px;
    border-radius: var(--border-radius-sm);
    margin-bottom: var(--spacing-sm);
    display: inline-block;
  }
  
  .description {
    margin-bottom: var(--spacing-sm);
  }
  
  .recommendations {
    margin-top: var(--spacing-sm);
    padding-top: var(--spacing-sm);
    border-top: 1px dashed var(--color-neutral);
  }
`;

const NoResultsMessage = styled.div`
  text-align: center;
  padding: var(--spacing-xl);
  
  svg {
    font-size: 48px;
    color: var(--color-neutral);
    margin-bottom: var(--spacing-md);
  }
  
  h3 {
    margin-bottom: var(--spacing-md);
    color: var(--color-text-primary);
  }
  
  p {
    color: var(--color-text-secondary);
    max-width: 600px;
    margin: 0 auto var(--spacing-lg);
  }
`;

// Animation variants
const fadeIn = {
  hidden: { opacity: 0, y: 20 },
  visible: { 
    opacity: 1, 
    y: 0,
    transition: { duration: 0.6 }
  }
};

const ResultsPage = () => {
  const navigate = useNavigate();
  const [analysisResult, setAnalysisResult] = useState(null);
  
  useEffect(() => {
    // Retrieve analysis result from localStorage
    const storedResult = localStorage.getItem('analysisResult');
    
    if (storedResult) {
      try {
        setAnalysisResult(JSON.parse(storedResult));
      } catch (err) {
        console.error('Error parsing analysis result:', err);
      }
    }
  }, []);
  
  const handleNewAnalysis = () => {
    navigate('/analyze');
  };
  
  const handleDownloadReport = () => {
    if (!analysisResult) return;
    
    // Create a blob with the report content
    const blob = new Blob([analysisResult.final_report], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    
    // Create a temporary link and trigger download
    const a = document.createElement('a');
    a.href = url;
    a.download = 'ai-mammoth-analysis-report.md';
    document.body.appendChild(a);
    a.click();
    
    // Clean up
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };
  
  const handleViewVisualizations = () => {
    navigate('/visualization');
  };
  
  // Helper function to get severity icon
  const getSeverityIcon = (severity) => {
    switch(severity) {
      case 'critical':
        return <FiAlertCircle color="var(--color-error)" />;
      case 'high':
        return <FiAlertCircle color="var(--color-warning)" />;
      case 'medium':
        return <FiInfo color="var(--color-warning-light)" />;
      case 'low':
        return <FiInfo color="var(--color-info)" />;
      default:
        return <FiInfo color="var(--color-neutral)" />;
    }
  };
  
  return (
    <PageContainer>
      <motion.div 
        initial="hidden"
        animate="visible"
        variants={fadeIn}
      >
        <PageHeader>
          <Title>Результаты анализа</Title>
          <Subtitle>
            Детальный отчет о проведенном анализе кода с выявленными проблемами и рекомендациями
          </Subtitle>
        </PageHeader>
        
        {!analysisResult ? (
          <NoResultsMessage>
            <FiInfo />
            <h3>Нет доступных результатов</h3>
            <p>
              Результаты анализа не найдены. Возможно, вы еще не проводили анализ или результаты были очищены.
            </p>
            <Button variant="gradient" onClick={handleNewAnalysis}>
              Начать новый анализ
            </Button>
          </NoResultsMessage>
        ) : (
          <>
            <ResultsContainer>
              <ResultsHeader>
                <ResultsTitle>
                  <FiCheckCircle /> Отчет об анализе
                </ResultsTitle>
                <ResultsActions>
                  <Button variant="outlined" onClick={handleDownloadReport}>
                    <FiDownload /> Скачать отчет
                  </Button>
                  {analysisResult.enhanced_features_available && (
                    <Button variant="gradient" onClick={handleViewVisualizations}>
                      <FiBarChart2 /> Визуализация
                    </Button>
                  )}
                </ResultsActions>
              </ResultsHeader>
              
              <StatsContainer>
                <StatCard color="var(--color-error)">
                  <h3>Найдено багов</h3>
                  <div className="value">{analysisResult.bugs_count}</div>
                </StatCard>
                {analysisResult.security_vulnerabilities && (
                  <StatCard color="var(--color-warning)">
                    <h3>Уязвимости</h3>
                    <div className="value">{analysisResult.security_vulnerabilities.length}</div>
                  </StatCard>
                )}
                {analysisResult.recommendations && (
                  <StatCard color="var(--color-info)">
                    <h3>Рекомендации</h3>
                    <div className="value">{analysisResult.recommendations.length}</div>
                  </StatCard>
                )}
              </StatsContainer>
              
              <ResultsContent>
                <ReactMarkdown>{analysisResult.final_report}</ReactMarkdown>
              </ResultsContent>
              
              {analysisResult.detailed_bugs && analysisResult.detailed_bugs.length > 0 && (
                <BugsList>
                  <h2>Детальное описание проблем</h2>
                  {analysisResult.detailed_bugs.map((bug, index) => (
                    <BugItem key={index} severity={bug.severity.toLowerCase()}>
                      <h4>
                        {getSeverityIcon(bug.severity.toLowerCase())}
                        {bug.description}
                      </h4>
                      {bug.location && <div className="location">{bug.location}</div>}
                      <div className="description">{bug.cause}</div>
                      <div className="impact"><strong>Влияние:</strong> {bug.impact}</div>
                      <div className="recommendations">
                        <strong>Рекомендации:</strong> {bug.recommendations}
                      </div>
                    </BugItem>
                  ))}
                </BugsList>
              )}
            </ResultsContainer>
            
            <div style={{ textAlign: 'center' }}>
              <Button variant="gradient" onClick={handleNewAnalysis}>
                Начать новый анализ
              </Button>
            </div>
          </>
        )}
      </motion.div>
    </PageContainer>
  );
};

export default ResultsPage; 