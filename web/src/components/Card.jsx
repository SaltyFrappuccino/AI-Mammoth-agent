import React from 'react';
import styled from 'styled-components';
import { motion } from 'framer-motion';

const StyledCard = styled(motion.div)`
  background-color: #ffffff;
  border-radius: 12px;
  padding: 2rem;
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.08);
  transition: all 0.3s ease;
  overflow: hidden;
  position: relative;
  
  ${({ variant }) => variant === 'bordered' && `
    border: 1px solid #e0e0e0;
  `}

  ${({ variant }) => variant === 'gradient' && `
    background: linear-gradient(135deg, #ffffff 0%, #f7f7f7 100%);
    border-left: 4px solid #21A038;
  `}
  
  ${({ variant }) => variant === 'sber' && `
    border-radius: 8px 8px 12px 12px;
    
    &:before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 4px;
      background: linear-gradient(
        to right,
        #21A038 0%,
        #6ECF81 33%,
        #FDD835 66%,
        #0087CD 100%
      );
    }
  `}
`;

const CardTitle = styled.h3`
  font-size: 1.25rem;
  font-weight: 600;
  margin-top: 0;
  margin-bottom: 0.75rem;
  color: #333333;
  font-family: 'SB Sans Display', sans-serif;
`;

const CardContent = styled.div`
  color: #666666;
  font-family: 'SB Sans Display', sans-serif;
`;

const CardFooter = styled.div`
  margin-top: 1.5rem;
  padding-top: 1.5rem;
  border-top: 1px solid #e0e0e0;
  display: flex;
  justify-content: space-between;
  align-items: center;
`;

// Анимационные варианты для карточки
const cardVariants = {
  initial: { 
    scale: 1,
    y: 0,
    boxShadow: '0 4px 16px rgba(0, 0, 0, 0.08)'
  },
  hover: { 
    scale: 1.02,
    y: -5,
    boxShadow: '0 8px 24px rgba(0, 0, 0, 0.12)',
    transition: { 
      type: 'spring', 
      stiffness: 300, 
      damping: 15 
    }
  },
  tap: { 
    scale: 0.98,
    boxShadow: '0 2px 8px rgba(0, 0, 0, 0.05)',
    transition: { 
      type: 'spring', 
      stiffness: 500, 
      damping: 20 
    } 
  }
};

const Card = ({ 
  title, 
  children, 
  footer,
  variant = 'default', // default, bordered, gradient, sber
  interactive = true,
  className,
  ...props 
}) => {
  return (
    <StyledCard 
      className={className}
      variant={variant}
      initial="initial"
      whileHover={interactive ? "hover" : undefined}
      whileTap={interactive ? "tap" : undefined}
      variants={cardVariants}
      {...props}
    >
      {title && <CardTitle>{title}</CardTitle>}
      <CardContent>{children}</CardContent>
      {footer && <CardFooter>{footer}</CardFooter>}
    </StyledCard>
  );
};

export default Card; 