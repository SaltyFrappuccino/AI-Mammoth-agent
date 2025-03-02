import React from 'react';
import styled from 'styled-components';
import { Link } from 'react-router-dom';
import { FiGithub, FiMail, FiExternalLink } from 'react-icons/fi';

// Стилизованные компоненты
const FooterContainer = styled.footer`
  background-color: var(--color-white);
  border-top: 1px solid var(--color-neutral-light);
  padding: var(--spacing-lg) 0;
  margin-top: auto;
`;

const FooterContent = styled.div`
  display: flex;
  flex-direction: column;
  max-width: 1200px;
  margin: 0 auto;
  padding: 0 var(--spacing-lg);
  gap: var(--spacing-lg);
  
  @media (min-width: 768px) {
    flex-direction: row;
    justify-content: space-between;
  }
`;

const FooterSection = styled.div`
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
`;

const FooterTitle = styled.h3`
  font-size: var(--font-size-md);
  font-weight: 600;
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-sm);
`;

const FooterLink = styled(Link)`
  color: var(--color-text-secondary);
  text-decoration: none;
  transition: color 0.2s ease;
  display: flex;
  align-items: center;
  gap: var(--spacing-xs);
  
  &:hover {
    color: var(--color-primary);
  }
`;

const ExternalLink = styled.a`
  color: var(--color-text-secondary);
  text-decoration: none;
  transition: color 0.2s ease;
  display: flex;
  align-items: center;
  gap: var(--spacing-xs);
  
  &:hover {
    color: var(--color-primary);
  }
`;

const FooterText = styled.p`
  color: var(--color-text-secondary);
  font-size: var(--font-size-sm);
  line-height: 1.5;
  margin: 0;
`;

const CopyrightBar = styled.div`
  margin-top: var(--spacing-lg);
  padding-top: var(--spacing-md);
  border-top: 1px solid var(--color-neutral-light);
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: var(--spacing-sm);
  
  @media (min-width: 768px) {
    flex-direction: row;
    justify-content: space-between;
  }
`;

const LegalLinks = styled.div`
  display: flex;
  gap: var(--spacing-md);
  flex-wrap: wrap;
  justify-content: center;
  
  @media (min-width: 768px) {
    justify-content: flex-end;
  }
`;

const SocialLinks = styled.div`
  display: flex;
  gap: var(--spacing-md);
  margin-top: var(--spacing-sm);
`;

const SocialIcon = styled(ExternalLink)`
  font-size: 1.25rem;
  color: var(--color-neutral);
  
  &:hover {
    color: var(--color-primary);
  }
`;

const GradientBar = styled.div`
  height: 4px;
  width: 100%;
  background: linear-gradient(
    to right,
    var(--color-primary) 0%,
    var(--color-spring) 33%,
    var(--color-sun) 66%,
    var(--color-secondary) 100%
  );
  margin-top: var(--spacing-md);
`;

// Компонент Footer
const Footer = () => {
  const currentYear = new Date().getFullYear();
  
  return (
    <FooterContainer>
      <FooterContent>
        <FooterSection>
          <FooterTitle>AI-Mammoth</FooterTitle>
          <FooterText>
            Инновационная система анализа кода на базе 
            искусственного интеллекта для повышения 
            качества и надежности разрабатываемого ПО.
          </FooterText>
        </FooterSection>
        
        <FooterSection>
          <FooterTitle>Навигация</FooterTitle>
          <FooterLink to="/">Главная</FooterLink>
          <FooterLink to="/analyze">Анализ кода</FooterLink>
          <FooterLink to="/results">Результаты</FooterLink>
          <FooterLink to="/visualization">Визуализация</FooterLink>
        </FooterSection>
        
        <FooterSection>
          <FooterTitle>Ресурсы</FooterTitle>
          <ExternalLink href="https://github.com/SaltyFrappuccino/AI-Mammoth-agent" target="_blank">
            Документация <FiExternalLink size={14} />
          </ExternalLink>
          <ExternalLink href="https://github.com/SaltyFrappuccino/AI-Mammoth-agent/issues" target="_blank">
            Сообщить о проблеме <FiExternalLink size={14} />
          </ExternalLink>
          <ExternalLink href="https://github.com/SaltyFrappuccino/AI-Mammoth-agent" target="_blank">
            GitHub репозиторий <FiGithub size={14} />
          </ExternalLink>
          <SocialLinks>
            <SocialIcon href="https://github.com/SaltyFrappuccino/AI-Mammoth-agent" target="_blank" aria-label="GitHub">
              <FiGithub />
            </SocialIcon>
          </SocialLinks>
        </FooterSection>
      </FooterContent>
      
      <FooterContent>
        <CopyrightBar>
          <FooterText>
            © {currentYear} AI-Mammoth. Все права защищены.
          </FooterText>
          
          <LegalLinks>
            <FooterLink to="/terms">Условия использования</FooterLink>
            <FooterLink to="/privacy">Политика конфиденциальности</FooterLink>
            <FooterLink to="/documentation">Документация</FooterLink>
          </LegalLinks>
        </CopyrightBar>
      </FooterContent>
      
      <GradientBar />
    </FooterContainer>
  );
};

export default Footer; 