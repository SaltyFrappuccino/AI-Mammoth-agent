import React from 'react';
import styled, { css } from 'styled-components';
import { motion } from 'framer-motion';

// Базовый стиль для всех кнопок
const BaseButton = styled(motion.button)`
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-family: 'SB Sans Display', sans-serif;
  font-weight: 500;
  border: none;
  cursor: pointer;
  transition: all 0.3s ease;
  padding: 0 1.5rem;
  height: ${props => props.size === 'small' 
    ? '2.5rem' 
    : props.size === 'large' 
      ? '3.5rem' 
      : '3rem'};
  border-radius: ${props => props.rounded ? '50px' : '8px'};
  font-size: ${props => props.size === 'small' 
    ? '0.875rem' 
    : props.size === 'large' 
      ? '1.125rem' 
      : '1rem'};
  gap: 0.5rem;
  
  &:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  ${props => props.fullWidth && css`
    width: 100%;
  `}
`;

// Первичная кнопка (зеленая)
const PrimaryButton = styled(BaseButton)`
  background-color: #21A038;
  color: #ffffff;
  box-shadow: 0 2px 8px rgba(33, 160, 56, 0.2);

  &:hover:not(:disabled) {
    background-color: #1c8c30;
    box-shadow: 0 4px 12px rgba(33, 160, 56, 0.3);
    transform: translateY(-2px);
  }

  &:active:not(:disabled) {
    background-color: #1c8c30;
    box-shadow: 0 2px 8px rgba(33, 160, 56, 0.2);
    transform: translateY(0);
  }
`;

// Вторичная кнопка (синяя)
const SecondaryButton = styled(BaseButton)`
  background-color: #0087CD;
  color: #ffffff;
  box-shadow: 0 2px 8px rgba(0, 135, 205, 0.2);

  &:hover:not(:disabled) {
    background-color: #0073b1;
    box-shadow: 0 4px 12px rgba(0, 135, 205, 0.3);
    transform: translateY(-2px);
  }

  &:active:not(:disabled) {
    background-color: #0073b1;
    box-shadow: 0 2px 8px rgba(0, 135, 205, 0.2);
    transform: translateY(0);
  }
`;

// Обводная кнопка
const OutlinedButton = styled(BaseButton)`
  background-color: transparent;
  color: #21A038;
  border: 2px solid #21A038;

  &:hover:not(:disabled) {
    background-color: rgba(33, 160, 56, 0.1);
    transform: translateY(-2px);
  }

  &:active:not(:disabled) {
    background-color: rgba(33, 160, 56, 0.1);
    transform: translateY(0);
  }
`;

// Текстовая кнопка
const TextButton = styled(BaseButton)`
  background-color: transparent;
  color: #21A038;
  padding: 0 0.75rem;
  height: auto;

  &:hover:not(:disabled) {
    color: #1c8c30;
    background-color: rgba(33, 160, 56, 0.1);
    border-radius: 8px;
  }
`;

// Кнопка с градиентом Сбера
const GradientButton = styled(BaseButton)`
  background: linear-gradient(
    135deg, 
    #21A038 0%, 
    #6ECF81 50%, 
    #0087CD 100%
  );
  color: #ffffff;
  box-shadow: 0 4px 12px rgba(33, 160, 56, 0.25);
  position: relative;
  z-index: 1;
  overflow: hidden;

  &:before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: linear-gradient(
      135deg, 
      #1c8c30 0%, 
      #6ECF81 50%, 
      #0073b1 100%
    );
    z-index: -1;
    opacity: 0;
    transition: opacity 0.3s ease;
  }

  &:hover:not(:disabled) {
    box-shadow: 0 6px 16px rgba(33, 160, 56, 0.3);
    transform: translateY(-2px);
    
    &:before {
      opacity: 1;
    }
  }

  &:active:not(:disabled) {
    box-shadow: 0 4px 12px rgba(33, 160, 56, 0.25);
    transform: translateY(0);
  }
`;

// Анимации для кнопок с использованием Framer Motion
const buttonVariants = {
  hover: { 
    scale: 1.03, 
    transition: { 
      type: 'spring', 
      stiffness: 400, 
      damping: 10 
    } 
  },
  tap: { 
    scale: 0.97, 
    transition: { 
      type: 'spring', 
      stiffness: 400, 
      damping: 10 
    } 
  }
};

// Экспортируемые компоненты кнопок с общими пропсами
const Button = ({ variant = 'primary', children, ...props }) => {
  const ButtonComponent = {
    primary: PrimaryButton,
    secondary: SecondaryButton,
    outlined: OutlinedButton,
    text: TextButton,
    gradient: GradientButton
  }[variant] || PrimaryButton;

  return (
    <ButtonComponent 
      whileHover="hover"
      whileTap="tap"
      variants={buttonVariants}
      {...props}
    >
      {children}
    </ButtonComponent>
  );
};

export default Button; 