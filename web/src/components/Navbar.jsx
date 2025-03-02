import React, { useState, useEffect } from 'react';
import styled from 'styled-components';
import { motion, AnimatePresence } from 'framer-motion';
import { Link, useLocation } from 'react-router-dom';
import { FiMenu, FiX } from 'react-icons/fi';

// Лого Сбера


// Стилизованные компоненты
const NavbarContainer = styled.nav`
  background-color: var(--color-white);
  box-shadow: var(--shadow-md);
  position: sticky;
  top: 0;
  z-index: 1000;
  padding: var(--spacing-md) var(--spacing-lg);
  display: flex;
  justify-content: space-between;
  align-items: center;
  transition: all 0.3s ease;
`;

const LogoContainer = styled(Link)`
  display: flex;
  align-items: center;
  text-decoration: none;
  color: var(--color-text-primary);

  h1 {
    margin-left: var(--spacing-sm);
    font-size: var(--font-size-lg);
    font-weight: 600;
  }
`;

const NavLinks = styled.div`
  display: flex;
  align-items: center;
  gap: var(--spacing-lg);

  @media (max-width: 768px) {
    display: none;
  }
`;

const NavLink = styled(Link)`
  text-decoration: none;
  color: var(--color-text-secondary);
  font-weight: 500;
  position: relative;
  transition: color 0.3s ease;
  
  &:hover {
    color: var(--color-primary);
  }
  
  &.active {
    color: var(--color-primary);
    
    &:after {
      content: '';
      position: absolute;
      bottom: -5px;
      left: 0;
      width: 100%;
      height: 2px;
      background-color: var(--color-primary);
      border-radius: var(--border-radius-sm);
    }
  }
`;

const MenuButton = styled.button`
  display: none;
  background: none;
  border: none;
  color: var(--color-text-primary);
  font-size: 24px;
  cursor: pointer;
  
  @media (max-width: 768px) {
    display: flex;
    align-items: center;
    justify-content: center;
  }
`;

const MobileMenu = styled(motion.div)`
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100vh;
  background-color: var(--color-white);
  z-index: 1100;
  padding: var(--spacing-lg);
  display: flex;
  flex-direction: column;
`;

const MobileMenuHeader = styled.div`
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-lg);
`;

const MobileNavLinks = styled.div`
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
  padding-top: var(--spacing-lg);
`;

const MobileNavLink = styled(NavLink)`
  font-size: var(--font-size-lg);
  padding: var(--spacing-sm) 0;
  
  &.active:after {
    bottom: -2px;
  }
`;

// Анимационные варианты
const mobileMenuVariants = {
  closed: {
    x: '100%',
    transition: {
      type: 'spring',
      stiffness: 300,
      damping: 30
    }
  },
  open: {
    x: 0,
    transition: {
      type: 'spring',
      stiffness: 300,
      damping: 30
    }
  }
};

// Компонент Navbar
const Navbar = ({ appName = "AI-Mammoth", links = [] }) => {
  const [isOpen, setIsOpen] = useState(false);
  const location = useLocation();
  
  // Закрытие мобильного меню при изменении маршрута
  useEffect(() => {
    setIsOpen(false);
  }, [location]);

  // Закрытие мобильного меню при нажатии клавиши Escape
  useEffect(() => {
    const handleEsc = (event) => {
      if (event.keyCode === 27) setIsOpen(false);
    };
    window.addEventListener('keydown', handleEsc);
    
    return () => {
      window.removeEventListener('keydown', handleEsc);
    };
  }, []);

  // Блокировка прокрутки при открытом мобильном меню
  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = 'unset';
    }
    
    return () => {
      document.body.style.overflow = 'unset';
    };
  }, [isOpen]);

  // Определение активного маршрута
  const isActiveRoute = (path) => {
    return location.pathname === path;
  };

  // Навигационные ссылки по умолчанию, если не переданы
  const defaultLinks = [
    { to: '/', label: 'Главная' },
    { to: '/analyze', label: 'Анализ кода' },
    { to: '/results', label: 'Результаты' },
    { to: '/visualization', label: 'Визуализация' },
    { to: '/documentation', label: 'Документация' },
  ];

  const navLinks = links.length > 0 ? links : defaultLinks;

  return (
    <NavbarContainer>
      <LogoContainer to="/">
        <h1>{appName}</h1>
      </LogoContainer>
      
      <NavLinks>
        {navLinks.map((link) => (
          <NavLink 
            key={link.to}
            to={link.to}
            className={isActiveRoute(link.to) ? 'active' : ''}
          >
            {link.label}
          </NavLink>
        ))}
      </NavLinks>
      
      <MenuButton onClick={() => setIsOpen(true)}>
        <FiMenu />
      </MenuButton>
      
      <AnimatePresence>
        {isOpen && (
          <MobileMenu
            initial="closed"
            animate="open"
            exit="closed"
            variants={mobileMenuVariants}
          >
            <MobileMenuHeader>
              <LogoContainer to="/">
                <h1>{appName}</h1>
              </LogoContainer>
              <MenuButton onClick={() => setIsOpen(false)}>
                <FiX />
              </MenuButton>
            </MobileMenuHeader>
            
            <MobileNavLinks>
              {navLinks.map((link) => (
                <MobileNavLink 
                  key={link.to}
                  to={link.to}
                  className={isActiveRoute(link.to) ? 'active' : ''}
                >
                  {link.label}
                </MobileNavLink>
              ))}
            </MobileNavLinks>
          </MobileMenu>
        )}
      </AnimatePresence>
    </NavbarContainer>
  );
};

export default Navbar; 