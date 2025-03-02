import React, { forwardRef } from 'react';
import styled, { css } from 'styled-components';
import { motion } from 'framer-motion';

// Стили для контейнера поля ввода
const InputContainer = styled.div`
  display: flex;
  flex-direction: column;
  margin-bottom: var(--spacing-md);
  width: 100%;
`;

// Стили для метки поля ввода
const InputLabel = styled.label`
  font-size: var(--font-size-sm);
  font-weight: 500;
  margin-bottom: var(--spacing-xs);
  color: var(--color-text-secondary);
  transition: color 0.2s ease;
`;

// Общие стили для элемента ввода
const inputStyles = css`
  font-family: 'SB Sans Display', sans-serif;
  font-size: var(--font-size-md);
  color: var(--color-text-primary);
  background-color: var(--color-white);
  border: 1px solid var(--color-neutral-light);
  border-radius: var(--border-radius-md);
  padding: var(--spacing-sm) var(--spacing-md);
  transition: all 0.2s ease-in-out;
  outline: none;
  width: 100%;
  height: ${props => props.size === 'small' 
    ? 'var(--spacing-lg)' 
    : props.size === 'large' 
      ? 'var(--spacing-xl)' 
      : '42px'};

  &:hover {
    border-color: var(--color-primary-light);
  }

  &:focus {
    border-color: var(--color-primary);
    box-shadow: 0 0 0 3px var(--color-primary-light);
  }

  &:disabled {
    background-color: var(--color-neutral-light);
    cursor: not-allowed;
    opacity: 0.7;
  }

  &::placeholder {
    color: var(--color-neutral);
  }

  ${props => props.error && css`
    border-color: var(--color-error);
    
    &:focus {
      box-shadow: 0 0 0 3px var(--color-error-light);
    }
  `}

  ${props => props.success && css`
    border-color: var(--color-success);
    
    &:focus {
      box-shadow: 0 0 0 3px var(--color-success-light);
    }
  `}

  ${props => props.variant === 'filled' && css`
    background-color: var(--color-neutral-light);
    border: 1px solid transparent;

    &:hover {
      background-color: var(--color-snow);
    }

    &:focus {
      background-color: var(--color-white);
      border-color: var(--color-primary);
    }
  `}

  ${props => props.icon && css`
    padding-left: ${props.iconPosition === 'right' ? 'var(--spacing-md)' : '2.5rem'};
    padding-right: ${props.iconPosition === 'right' ? '2.5rem' : 'var(--spacing-md)'};
  `}
`;

// Стили для текстового поля ввода
const StyledInput = styled.input`
  ${inputStyles}
`;

// Стили для текстовой области
const StyledTextarea = styled.textarea`
  ${inputStyles}
  resize: ${props => props.resize || 'vertical'};
  min-height: ${props => props.minHeight || '100px'};
`;

// Стили для сообщения об ошибке
const ErrorMessage = styled.div`
  color: var(--color-error);
  font-size: var(--font-size-sm);
  margin-top: var(--spacing-xs);
`;

// Стили для вспомогательного текста
const HelperText = styled.div`
  color: var(--color-text-secondary);
  font-size: var(--font-size-sm);
  margin-top: var(--spacing-xs);
`;

// Стили для контейнера иконки
const IconContainer = styled.div`
  position: absolute;
  top: 50%;
  transform: translateY(-50%);
  ${props => props.position === 'left' ? 'left: 12px;' : 'right: 12px;'}
  color: var(--color-neutral);
  display: flex;
  align-items: center;
  justify-content: center;
  pointer-events: ${props => props.clickable ? 'auto' : 'none'};
  cursor: ${props => props.clickable ? 'pointer' : 'default'};
`;

// Стили для обертки ввода с иконкой
const InputWrapper = styled.div`
  position: relative;
  width: 100%;
  display: flex;
  align-items: center;
`;

// Компонент для анимации метки формы
const AnimatedLabel = styled(motion.span)`
  display: inline-block;
`;

// Анимационные варианты для метки
const labelVariants = {
  focused: { 
    color: 'var(--color-primary)',
    y: -2,
    transition: { 
      type: 'spring', 
      stiffness: 500, 
      damping: 30 
    } 
  },
  blurred: { 
    color: 'var(--color-text-secondary)',
    y: 0
  }
};

// Основной компонент Input
const Input = forwardRef(({ 
  id,
  label,
  type = 'text',
  placeholder,
  error,
  helperText,
  icon,
  iconPosition = 'left',
  onIconClick,
  multiline = false,
  success,
  variant = 'outlined', // outlined или filled
  size = 'medium', // small, medium, large
  className,
  ...props 
}, ref) => {
  const [focused, setFocused] = React.useState(false);

  const handleFocus = (e) => {
    setFocused(true);
    if (props.onFocus) props.onFocus(e);
  };

  const handleBlur = (e) => {
    setFocused(false);
    if (props.onBlur) props.onBlur(e);
  };

  const inputId = id || `input-${Math.random().toString(36).substring(2, 9)}`;

  return (
    <InputContainer className={className}>
      {label && (
        <InputLabel htmlFor={inputId}>
          <AnimatedLabel
            variants={labelVariants}
            animate={focused ? 'focused' : 'blurred'}
          >
            {label}
          </AnimatedLabel>
        </InputLabel>
      )}
      <InputWrapper>
        {icon && (
          <IconContainer 
            position={iconPosition} 
            clickable={!!onIconClick}
            onClick={onIconClick}
          >
            {icon}
          </IconContainer>
        )}
        {multiline ? (
          <StyledTextarea
            id={inputId}
            ref={ref}
            placeholder={placeholder}
            error={!!error}
            success={success}
            variant={variant}
            size={size}
            icon={!!icon}
            iconPosition={iconPosition}
            onFocus={handleFocus}
            onBlur={handleBlur}
            {...props}
          />
        ) : (
          <StyledInput
            id={inputId}
            ref={ref}
            type={type}
            placeholder={placeholder}
            error={!!error}
            success={success}
            variant={variant}
            size={size}
            icon={!!icon}
            iconPosition={iconPosition}
            onFocus={handleFocus}
            onBlur={handleBlur}
            {...props}
          />
        )}
      </InputWrapper>
      {error && <ErrorMessage>{error}</ErrorMessage>}
      {helperText && !error && <HelperText>{helperText}</HelperText>}
    </InputContainer>
  );
});

Input.displayName = 'Input';

export default Input; 