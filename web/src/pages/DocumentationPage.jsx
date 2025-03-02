import React, { useEffect, useState } from 'react';
import styled from 'styled-components';
import { motion } from 'framer-motion';
import ReactMarkdown from 'react-markdown';
import { FiFileText, FiBookOpen } from 'react-icons/fi';
import axios from 'axios';

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

const DocumentationContent = styled.div`
  background-color: white;
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-lg);
  box-shadow: var(--shadow-md);
  
  h1, h2, h3, h4, h5, h6 {
    color: var(--color-primary);
    margin-top: var(--spacing-lg);
    margin-bottom: var(--spacing-md);
  }
  
  h1 {
    border-bottom: 2px solid var(--color-primary-light);
    padding-bottom: var(--spacing-sm);
  }
  
  h2 {
    border-bottom: 1px solid var(--color-neutral-light);
    padding-bottom: var(--spacing-sm);
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
  
  img {
    max-width: 100%;
    border-radius: var(--border-radius-md);
    margin: var(--spacing-md) 0;
  }
  
  a {
    color: var(--color-primary);
    text-decoration: none;
    
    &:hover {
      text-decoration: underline;
    }
  }
  
  table {
    width: 100%;
    border-collapse: collapse;
    margin-bottom: var(--spacing-md);
    
    th, td {
      border: 1px solid var(--color-neutral-light);
      padding: var(--spacing-sm);
    }
    
    th {
      background-color: var(--color-neutral-light);
    }
    
    tr:nth-child(even) {
      background-color: var(--color-neutral-ultralight);
    }
  }
`;

const LoadingContainer = styled.div`
  display: flex;
  justify-content: center;
  align-items: center;
  height: 300px;
  color: var(--color-primary);
  font-size: var(--font-size-lg);
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

const DocumentationPage = () => {
  const [content, setContent] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  
  useEffect(() => {
    const fetchDocumentation = async () => {
      try {
        setIsLoading(true);
        // Fetch README.md content using relative path
        const response = await axios.get('/README.md');
        setContent(response.data);
      } catch (err) {
        console.error('Error loading documentation:', err);
        setError('Не удалось загрузить документацию. Пожалуйста, попробуйте позже.');
        
        // Fallback to the static README content
        // This is a backup in case the file can't be loaded
        const staticReadme = `# AI-Mammoth Code Analysis System

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.95.0%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![GigaChat](https://img.shields.io/badge/LLM-GigaChat-orange.svg)](https://developers.sber.ru/portal/products/gigachat)
[![LangChain](https://img.shields.io/badge/LangChain-0.1.0%2B-34D058.svg)](https://langchain.com/)
[![Spring Boot](https://img.shields.io/badge/Spring_Boot-2.7%2B-6DB33F.svg)](https://spring.io/projects/spring-boot)
[![Docker](https://img.shields.io/badge/Docker-Supported-2496ED.svg)](https://www.docker.com/)
[![ChromaDB](https://img.shields.io/badge/Vector_DB-ChromaDB-blueviolet.svg)](https://www.trychroma.com/)
![Code Size](https://img.shields.io/badge/Code%20Size-50K%2B%20lines-informational)
[![Documentation](https://img.shields.io/badge/Documentation-Comprehensive-blue.svg)](https://github.com/)
[![Activity](https://img.shields.io/badge/Activity-High-brightgreen.svg)](https://github.com/)
[![JIRA Integration](https://img.shields.io/badge/Integration-JIRA-0052CC.svg)](https://www.atlassian.com/software/jira)
[![Bitbucket Integration](https://img.shields.io/badge/Integration-Bitbucket-0052CC.svg)](https://bitbucket.org/)
[![Confluence Integration](https://img.shields.io/badge/Integration-Confluence-0052CC.svg)](https://www.atlassian.com/software/confluence)
[![Zephyr Integration](https://img.shields.io/badge/Integration-Zephyr-00B5D1.svg)](https://smartbear.com/test-management/zephyr/)

## Описание проекта

**AI-Mammoth** — революционная система автоматического анализа и верификации кода, созданная для существенного снижения количества ошибок при разработке программного обеспечения и ускорения процесса разработки. Система использует передовые технологии искусственного интеллекта для непрерывного анализа артефактов разработки: требований, кода, тест-кейсов и документации.

**Важно:** Проект состоит из двух репозиториев:
1. **Основной репозиторий** (текущий) — содержит ядро системы анализа и AI-агентов
2. **[AI-Mammoth-spring](https://github.com/SaltyFrappuccino/AI-Mammoth-spring)** — содержит Spring-приложение, которое автоматизирует работу с ассистентом и позволяет в автоматическом режиме собирать информацию из Confluence, Bitbucket, Jira и Zephyr (тест-кейсы)`;
        
        setContent(staticReadme);
      } finally {
        setIsLoading(false);
      }
    };
    
    fetchDocumentation();
  }, []);
  
  return (
    <PageContainer>
      <motion.div 
        initial="hidden"
        animate="visible"
        variants={fadeIn}
      >
        <PageHeader>
          <Title>Документация</Title>
          <Subtitle>
            Подробная документация по системе AI-Mammoth, инструкции по использованию и техническая информация
          </Subtitle>
        </PageHeader>
        
        {isLoading ? (
          <LoadingContainer>
            <FiBookOpen size={40} /> Загрузка документации...
          </LoadingContainer>
        ) : error ? (
          <DocumentationContent>
            <h1>Ошибка загрузки</h1>
            <p>{error}</p>
          </DocumentationContent>
        ) : (
          <DocumentationContent>
            <ReactMarkdown>{content}</ReactMarkdown>
          </DocumentationContent>
        )}
      </motion.div>
    </PageContainer>
  );
};

export default DocumentationPage; 