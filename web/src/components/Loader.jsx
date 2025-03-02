import React from 'react';
import styled, { keyframes } from 'styled-components';
import { motion } from 'framer-motion';

// Анимация пульсации для логотипа
const pulse = keyframes`
  0% {
    transform: scale(0.95);
    box-shadow: 0 0 0 0 rgba(33, 160, 56, 0.7);
  }
  
  70% {
    transform: scale(1);
    box-shadow: 0 0 0 10px rgba(33, 160, 56, 0);
  }
  
  100% {
    transform: scale(0.95);
    box-shadow: 0 0 0 0 rgba(33, 160, 56, 0);
  }
`;

// Анимация вращения
const rotate = keyframes`
  from {
    transform: rotate(0deg);
  }
  to {
    transform: rotate(360deg);
  }
`;

// Контейнер лоадера
const LoaderContainer = styled.div`
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: ${props => props.fullScreen ? '100vh' : '100%'};
  width: 100%;
  background-color: ${props => props.overlay ? 'rgba(255, 255, 255, 0.9)' : 'transparent'};
  position: ${props => props.overlay ? 'fixed' : 'relative'};
  top: 0;
  left: 0;
  z-index: ${props => props.overlay ? '1000' : '1'};
`;

// Элемент с логотипом Сбера
const SberLogoWrapper = styled.div`
  position: relative;
  width: 80px;
  height: 80px;
  animation: ${pulse} 2s infinite;
`;

// Внешнее кольцо вокруг логотипа
const SpinnerRing = styled.div`
  position: absolute;
  width: 100px;
  height: 100px;
  border: 3px solid rgba(0, 0, 0, 0.1);
  border-top: 3px solid var(--color-primary);
  border-radius: 50%;
  animation: ${rotate} 1.5s linear infinite;
  top: -10px;
  left: -10px;
`;

// Текст загрузки
const LoadingText = styled(motion.p)`
  margin-top: var(--spacing-lg);
  color: var(--color-text-primary);
  font-size: var(--font-size-md);
  font-weight: 500;
`;

// SVG логотип Сбера для лоадера


// Варианты анимации для текста
const textVariants = {
  hidden: { opacity: 0, y: 20 },
  visible: { 
    opacity: 1, 
    y: 0,
    transition: { 
      delay: 0.3,
      duration: 0.5
    } 
  }
};

// Основной компонент Loader
const Loader = ({ 
  text = "Загрузка...", 
  fullScreen = false, 
  overlay = false 
}) => {
  return (
    <LoaderContainer fullScreen={fullScreen} overlay={overlay}>
      <SberLogoWrapper>
        <SpinnerRing />
      </SberLogoWrapper>
      
      <LoadingText
        initial="hidden"
        animate="visible"
        variants={textVariants}
      >
        {text}
      </LoadingText>
    </LoaderContainer>
  );
};

export default Loader; 