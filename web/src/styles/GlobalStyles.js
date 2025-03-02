import { createGlobalStyle } from 'styled-components';

// Using system fonts instead of external fonts to avoid CORS issues
const GlobalStyles = createGlobalStyle`
  /* System font stack that resembles SB Sans Display */
  @font-face {
    font-family: 'SB Sans Display';
    /* Fallback to system fonts */
    src: local('Segoe UI'), local('Roboto'), local('Helvetica Neue'), local('Arial');
    font-weight: 400;
    font-style: normal;
    font-display: swap;
  }

  @font-face {
    font-family: 'SB Sans Display';
    /* Fallback to system fonts */
    src: local('Segoe UI Light'), local('Roboto Light'), local('Helvetica Neue Light'), local('Arial');
    font-weight: 300;
    font-style: normal;
    font-display: swap;
  }

  @font-face {
    font-family: 'SB Sans Display';
    /* Fallback to system fonts */
    src: local('Segoe UI SemiBold'), local('Roboto Medium'), local('Helvetica Neue Medium'), local('Arial Bold');
    font-weight: 600;
    font-style: normal;
    font-display: swap;
  }

  @font-face {
    font-family: 'SB Sans Display';
    /* Fallback to system fonts */
    src: local('Segoe UI Bold'), local('Roboto Bold'), local('Helvetica Neue Bold'), local('Arial Bold');
    font-weight: 700;
    font-style: normal;
    font-display: swap;
  }

  :root {
    /* Цвета Сбера */
    --color-primary: #21A038;
    --color-primary-dark: #1c8c30;
    --color-primary-light: rgba(33, 160, 56, 0.1);
    
    --color-secondary: #0087CD;
    --color-secondary-dark: #0073b1;
    --color-secondary-light: rgba(0, 135, 205, 0.1);
    
    --color-spring: #6ECF81;
    --color-sun: #FDD835;
    --color-arctic: #85D9F0;
    
    --color-success: #21A038;
    --color-warning: #FDD835;
    --color-error: #F03226;
    
    --color-white: #ffffff;
    --color-snow: #f7f7f7;
    --color-background: #f5f5f5;
    --color-background-dark: #f0f0f0;
    
    --color-text-primary: #333333;
    --color-text-secondary: #666666;
    --color-neutral-light: #e0e0e0;
    --color-neutral: #9e9e9e;
    --color-neutral-dark: #616161;
    
    /* Размеры и отступы */
    --spacing-xs: 0.5rem;
    --spacing-sm: 0.75rem;
    --spacing-md: 1.5rem;
    --spacing-lg: 2rem;
    --spacing-xl: 4rem;
    
    /* Типографика */
    --font-family: 'SB Sans Display', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    --font-size-xs: 0.75rem;
    --font-size-sm: 0.875rem;
    --font-size-md: 1rem;
    --font-size-lg: 1.25rem;
    --font-size-xl: 1.5rem;
    --font-size-2xl: 2rem;
    --font-size-3xl: 2.5rem;
    --font-size-4xl: 3rem;
    
    /* Границы */
    --border-radius-sm: 4px;
    --border-radius-md: 8px;
    --border-radius-lg: 12px;
    --border-radius-xl: 16px;
    --border-radius-circular: 50px;
    
    /* Тени */
    --shadow-sm: 0 2px 8px rgba(0, 0, 0, 0.05);
    --shadow-md: 0 4px 16px rgba(0, 0, 0, 0.08);
    --shadow-lg: 0 8px 24px rgba(0, 0, 0, 0.12);
    --shadow-focus: 0 0 0 3px rgba(33, 160, 56, 0.2);
    
    /* Анимации */
    --animation-fast: 150ms;
    --animation-normal: 300ms;
    --animation-slow: 500ms;
    --animation-curve: cubic-bezier(0.4, 0, 0.2, 1);
  }

  * {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
  }

  html, body {
    font-family: var(--font-family);
    font-size: 16px;
    line-height: 1.5;
    color: var(--color-text-primary);
    background-color: var(--color-background);
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
    overflow-x: hidden;
    scroll-behavior: smooth;
    width: 100%;
    height: 100%;
  }

  #root {
    display: flex;
    flex-direction: column;
    min-height: 100vh;
  }

  main {
    flex: 1;
  }

  h1, h2, h3, h4, h5, h6 {
    font-weight: 600;
    margin-bottom: var(--spacing-md);
    line-height: 1.2;
    font-family: var(--font-family);
  }

  h1 {
    font-size: var(--font-size-4xl);
  }

  h2 {
    font-size: var(--font-size-3xl);
  }

  h3 {
    font-size: var(--font-size-2xl);
  }

  h4 {
    font-size: var(--font-size-xl);
  }

  h5 {
    font-size: var(--font-size-lg);
  }

  h6 {
    font-size: var(--font-size-md);
  }

  p {
    margin-bottom: var(--spacing-md);
    color: var(--color-text-secondary);
  }

  a {
    color: var(--color-secondary);
    text-decoration: none;
    transition: color var(--animation-fast) var(--animation-curve);
    
    &:hover {
      color: var(--color-secondary-dark);
      text-decoration: underline;
    }
  }

  button {
    font-family: var(--font-family);
    cursor: pointer;
  }

  ul, ol {
    list-style-position: inside;
    margin-bottom: var(--spacing-md);
  }

  img {
    max-width: 100%;
    height: auto;
  }

  .container {
    width: 100%;
    max-width: 1200px;
    margin: 0 auto;
    padding: 0 var(--spacing-md);
  }

  /* Стилизация для скролла */
  ::-webkit-scrollbar {
    width: 8px;
    height: 8px;
  }

  ::-webkit-scrollbar-track {
    background: var(--color-snow);
    border-radius: 4px;
  }

  ::-webkit-scrollbar-thumb {
    background: var(--color-neutral);
    border-radius: 4px;
    
    &:hover {
      background: var(--color-neutral-dark);
    }
  }

  /* Стили для фокуса */
  :focus {
    outline: none;
    box-shadow: var(--shadow-focus);
  }

  /* Стили для выделения текста */
  ::selection {
    background-color: var(--color-primary);
    color: var(--color-white);
  }
  
  /* Фикс для анимаций */
  .js-focus-visible :focus:not(.focus-visible) {
    outline: none;
    box-shadow: none;
  }
  
  /* Дополнительные улучшения доступности */
  [role="button"],
  button {
    cursor: pointer;
  }
  
  /* Улучшения для IE */
  @media all and (-ms-high-contrast: none), (-ms-high-contrast: active) {
    body {
      display: flex;
      flex-direction: column;
      min-height: 100vh;
    }
  }
`;

export default GlobalStyles; 