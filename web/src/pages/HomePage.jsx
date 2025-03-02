import React from 'react';
import styled from 'styled-components';
import { motion } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
import { 
  FiCode, 
  FiShield, 
  FiTrendingUp, 
  FiCpu, 
  FiActivity, 
  FiZap,
  FiArrowRight
} from 'react-icons/fi';

// Компоненты
import Button from '../components/Button';
import Card from '../components/Card';
import ParticlesBackground from '../components/ParticlesBackground';

// Стилизованные компоненты
const PageContainer = styled.div`
  position: relative;
  overflow: hidden;
  background-color: #f5f5f5;
`;

const HeroSection = styled.section`
  min-height: 80vh;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 4rem 2rem;
  text-align: center;
  position: relative;
  
  @media (max-width: 768px) {
    padding: 3rem 1.5rem;
  }
`;

const HeroContent = styled(motion.div)`
  max-width: 900px;
  z-index: 1;
  background-color: rgba(255, 255, 255, 0.9);
  padding: 3rem;
  border-radius: 16px;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
  backdrop-filter: blur(8px);
  border: 1px solid rgba(255, 255, 255, 0.2);
  
  @media (max-width: 768px) {
    padding: 2rem 1.5rem;
  }
`;

const HeroTitle = styled.h1`
  font-size: clamp(2.5rem, 5vw, 4rem);
  font-weight: 700;
  margin-bottom: 2rem;
  background: linear-gradient(135deg, #21A038 0%, #0087CD 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  line-height: 1.2;
  font-family: 'SB Sans Display', sans-serif;
`;

const HeroSubtitle = styled.p`
  font-size: clamp(1.2rem, 2vw, 1.5rem);
  color: #444;
  margin-bottom: 2.5rem;
  line-height: 1.6;
  font-family: 'SB Sans Display', sans-serif;
  font-weight: 300;
`;

const HeroButtons = styled.div`
  display: flex;
  gap: 1.5rem;
  justify-content: center;
  margin-top: 2rem;
  
  @media (max-width: 600px) {
    flex-direction: column;
    width: 100%;
    gap: 1rem;
  }
`;

const Section = styled.section`
  padding: 5rem 2rem;
  background-color: ${props => props.dark ? '#f0f0f0' : '#ffffff'};
  
  @media (max-width: 768px) {
    padding: 3rem 1.5rem;
  }
`;

const SectionTitle = styled.h2`
  font-size: 2.5rem;
  font-weight: 600;
  text-align: center;
  margin-bottom: 3rem;
  position: relative;
  color: #21A038;
  font-family: 'SB Sans Display', sans-serif;
  
  &:after {
    content: '';
    position: absolute;
    bottom: -15px;
    left: 50%;
    transform: translateX(-50%);
    width: 80px;
    height: 4px;
    background: linear-gradient(to right, #21A038, #0087CD);
    border-radius: 4px;
  }
`;

const FeaturesGrid = styled.div`
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 2rem;
  max-width: 1200px;
  margin: 0 auto;
  
  @media (max-width: 768px) {
    grid-template-columns: 1fr;
  }
`;

const FeatureCard = styled(Card)`
  display: flex;
  flex-direction: column;
  align-items: center;
  text-align: center;
  padding: 2rem;
  transition: transform 0.3s ease, box-shadow 0.3s ease;
  
  &:hover {
    transform: translateY(-10px);
    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
  }
  
  svg {
    font-size: 3rem;
    margin-bottom: 1.5rem;
    color: #21A038;
  }
  
  h3 {
    margin-bottom: 1rem;
    font-size: 1.5rem;
    color: #333;
    font-family: 'SB Sans Display', sans-serif;
    font-weight: 600;
  }
  
  p {
    color: #666;
    line-height: 1.6;
    font-family: 'SB Sans Display', sans-serif;
    font-weight: 300;
  }
`;

const StepsContainer = styled.div`
  max-width: 1000px;
  margin: 0 auto;
`;

const Step = styled.div`
  display: flex;
  margin-bottom: 3rem;
  position: relative;
  
  &:not(:last-child):after {
    content: '';
    position: absolute;
    left: 30px;
    top: 60px;
    bottom: -30px;
    width: 2px;
    background: linear-gradient(to bottom, #21A038, #0087CD);
  }
  
  @media (max-width: 768px) {
    flex-direction: column;
    
    &:not(:last-child):after {
      left: 50%;
      transform: translateX(-50%);
      top: 90px;
      width: 2px;
    }
  }
`;

const StepNumber = styled.div`
  width: 60px;
  height: 60px;
  border-radius: 50%;
  background: linear-gradient(135deg, #21A038 0%, #0087CD 100%);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1.5rem;
  font-weight: 600;
  color: white;
  margin-right: 2rem;
  flex-shrink: 0;
  box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
  
  @media (max-width: 768px) {
    margin: 0 auto 1.5rem;
  }
`;

const StepContent = styled.div`
  flex: 1;
  background-color: white;
  padding: 1.5rem;
  border-radius: 12px;
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.08);
  border-left: 4px solid #21A038;
  
  h3 {
    font-size: 1.5rem;
    margin-bottom: 0.75rem;
    color: #21A038;
    font-family: 'SB Sans Display', sans-serif;
    font-weight: 600;
  }
  
  p {
    color: #666;
    line-height: 1.6;
    font-family: 'SB Sans Display', sans-serif;
    font-weight: 300;
  }
  
  @media (max-width: 768px) {
    text-align: center;
  }
`;

const CtaSection = styled.section`
  padding: 5rem 2rem;
  background: linear-gradient(135deg, #21A038 0%, #0087CD 100%);
  text-align: center;
  color: white;
  position: relative;
  overflow: hidden;
  
  &:before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    opacity: 0.2;
  }
`;

const CtaTitle = styled.h2`
  font-size: 2.5rem;
  font-weight: 600;
  margin-bottom: 1.5rem;
  font-family: 'SB Sans Display', sans-serif;
  position: relative;
  z-index: 1;
`;

const CtaText = styled.p`
  font-size: 1.25rem;
  margin-bottom: 2.5rem;
  max-width: 800px;
  margin-left: auto;
  margin-right: auto;
  font-family: 'SB Sans Display', sans-serif;
  font-weight: 300;
  position: relative;
  z-index: 1;
`;

// Анимационные варианты
const fadeInUp = {
  hidden: { opacity: 0, y: 30 },
  visible: { 
    opacity: 1, 
    y: 0,
    transition: { 
      duration: 0.8,
      ease: "easeOut"
    } 
  }
};

const staggerContainer = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.2
    }
  }
};

// Основной компонент главной страницы
const HomePage = () => {
  const navigate = useNavigate();
  
  const handleAnalyzeClick = () => {
    navigate('/analyze');
  };
  
  return (
    <PageContainer>
      <ParticlesBackground />
      
      <HeroSection>
        <HeroContent
          initial="hidden"
          animate="visible"
          variants={fadeInUp}
        >
          <HeroTitle>
            AI-Mammoth: интеллектуальный анализ кода
          </HeroTitle>
          <HeroSubtitle>
            Повысьте качество вашего программного обеспечения с помощью продвинутого анализа кода 
            на основе искусственного интеллекта. Выявляйте потенциальные проблемы, получайте рекомендации
            и визуализируйте результаты в едином интерфейсе.
          </HeroSubtitle>
          
          <HeroButtons>
            <Button 
              variant="gradient" 
              size="large" 
              onClick={handleAnalyzeClick}
            >
              Начать анализ <FiArrowRight style={{ marginLeft: '8px' }} />
            </Button>
            <Button 
              variant="outlined" 
              size="large"
              onClick={() => navigate('/documentation')}
            >
              Узнать больше
            </Button>
          </HeroButtons>
        </HeroContent>
      </HeroSection>
      
      <Section>
        <SectionTitle>Преимущества AI-Mammoth</SectionTitle>
        <FeaturesGrid 
          as={motion.div}
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true, amount: 0.3 }}
          variants={staggerContainer}
        >
          <FeatureCard
            as={motion.div}
            variants={fadeInUp}
            variant="sber"
          >
            <FiShield />
            <h3>Повышение надежности</h3>
            <p>
              Выявление потенциальных ошибок и уязвимостей в коде до того, как они 
              попадут в продакшн.
            </p>
          </FeatureCard>
          
          <FeatureCard
            as={motion.div}
            variants={fadeInUp}
            variant="sber"
          >
            <FiTrendingUp />
            <h3>Улучшение производительности</h3>
            <p>
              Анализ и оптимизация кода для достижения максимальной 
              производительности и эффективности.
            </p>
          </FeatureCard>
          
          <FeatureCard
            as={motion.div}
            variants={fadeInUp}
            variant="sber"
          >
            <FiCpu />
            <h3>Искусственный интеллект</h3>
            <p>
              Использование передовых алгоритмов машинного обучения для глубокого 
              анализа кода и контекста.
            </p>
          </FeatureCard>
          
          <FeatureCard
            as={motion.div}
            variants={fadeInUp}
            variant="sber"
          >
            <FiCode />
            <h3>Проверка соответствия</h3>
            <p>
              Сопоставление кода с требованиями и стандартами, выявление расхождений и 
              несоответствий.
            </p>
          </FeatureCard>
          
          <FeatureCard
            as={motion.div}
            variants={fadeInUp}
            variant="sber"
          >
            <FiActivity />
            <h3>Наглядная визуализация</h3>
            <p>
              Интерактивные графики и диаграммы для лучшего понимания структуры и 
              качества кода.
            </p>
          </FeatureCard>
          
          <FeatureCard
            as={motion.div}
            variants={fadeInUp}
            variant="sber"
          >
            <FiZap />
            <h3>Быстрый результат</h3>
            <p>
              Мгновенный анализ и моментальное получение результатов с конкретными 
              рекомендациями.
            </p>
          </FeatureCard>
        </FeaturesGrid>
      </Section>
      
      <Section dark>
        <SectionTitle>Как это работает</SectionTitle>
        <StepsContainer>
          <motion.div
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true, amount: 0.3 }}
            variants={staggerContainer}
          >
            <Step as={motion.div} variants={fadeInUp}>
              <StepNumber>1</StepNumber>
              <StepContent>
                <h3>Загрузите код</h3>
                <p>
                  Загрузите исходный код вашего проекта. AI-Mammoth поддерживает множество языков программирования включая Python, 
                  Java, JavaScript, C++, и другие.
                </p>
              </StepContent>
            </Step>
            
            <Step as={motion.div} variants={fadeInUp}>
              <StepNumber>2</StepNumber>
              <StepContent>
                <h3>Добавьте требования</h3>
                <p>
                  Для более точного анализа вы можете добавить требования к проекту. Система сравнит код с требованиями и выявит 
                  несоответствия.
                </p>
              </StepContent>
            </Step>
            
            <Step as={motion.div} variants={fadeInUp}>
              <StepNumber>3</StepNumber>
              <StepContent>
                <h3>Добавьте тесты</h3>
                <p>
                  Загрузите тесты для вашего кода, чтобы система могла проанализировать покрытие и эффективность тестов.
                </p>
              </StepContent>
            </Step>
            
            <Step as={motion.div} variants={fadeInUp}>
              <StepNumber>4</StepNumber>
              <StepContent>
                <h3>Запустите анализ</h3>
                <p>
                  Искусственный интеллект проанализирует ваш код, сопоставит его с требованиями и тестами, проведет статический и 
                  динамический анализ.
                </p>
              </StepContent>
            </Step>
            
            <Step as={motion.div} variants={fadeInUp}>
              <StepNumber>5</StepNumber>
              <StepContent>
                <h3>Получите результаты</h3>
                <p>
                  Просмотрите детальный отчет с выявленными проблемами, рекомендациями по улучшению кода и визуальными 
                  представлениями результатов анализа.
                </p>
              </StepContent>
            </Step>
          </motion.div>
        </StepsContainer>
      </Section>
      
      <CtaSection>
        <motion.div
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true, amount: 0.3 }}
          variants={fadeInUp}
        >
          <CtaTitle>Готовы улучшить ваш код?</CtaTitle>
          <CtaText>
            Начните использовать AI-Mammoth прямо сейчас и повысьте качество вашего программного обеспечения
            с помощью продвинутого анализа кода на основе искусственного интеллекта.
          </CtaText>
          <Button 
            variant="outlined" 
            size="large"
            style={{
              color: 'white',
              borderColor: 'white',
              backgroundColor: 'rgba(255, 255, 255, 0.1)',
              padding: '0 2rem'
            }}
            onClick={handleAnalyzeClick}
          >
            Начать анализ <FiArrowRight style={{ marginLeft: '8px' }} />
          </Button>
        </motion.div>
      </CtaSection>
    </PageContainer>
  );
};

export default HomePage; 