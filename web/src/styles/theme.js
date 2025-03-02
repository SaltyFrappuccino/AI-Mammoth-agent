// Цветовая схема Сбера
const theme = {
  // Основные цвета
  colors: {
    primary: {
      main: '#21A038', // Зеленый СБЕР
      light: '#6ECF81',
      dark: '#1c8c30',
      contrastText: '#FFFFFF'
    },
    secondary: {
      main: '#0087CD', // Синий
      light: '#85D9F0',
      dark: '#0073b1',
      contrastText: '#FFFFFF'
    },
    success: {
      main: '#21A038', // Зеленый 
      light: '#6ECF81',
      dark: '#1c8c30',
      contrastText: '#FFFFFF'
    },
    warning: {
      main: '#FDD835', // Солнечный
      light: '#FEEB99',
      dark: '#F9CC27',
      contrastText: '#333333'
    },
    error: {
      main: '#F03226', // Красный
      light: '#FF5A4E',
      dark: '#D32F2F',
      contrastText: '#FFFFFF'
    },
    neutral: {
      main: '#9e9e9e', // Серый 
      light: '#e0e0e0',
      dark: '#616161',
      contrastText: '#FFFFFF'
    },
    white: '#FFFFFF',
    black: '#333333',
    
    // Дополнительные цвета из брендбука
    arctic: '#85D9F0', // Арктический
    emerald: '#21BA72', // Изумрудный
    spring: '#6ECF81', // Весенний
    sun: '#FDD835', // Солнечный
    orange: '#FF8000', // Оранжевый
    pink: '#FF0066', // Розовый
    
    // Оттенки серого
    graphite: '#313E47', // Графитовый
    snow: '#f7f7f7', // Снежный
    
    // Фоны
    background: '#f5f5f5',
    backgroundDark: '#f0f0f0',
    
    // Текст
    textPrimary: '#333333',
    textSecondary: '#666666',
    
    // Градиенты
    gradient: {
      main: 'linear-gradient(90deg, #21A038 0%, #6ECF81 25%, #FDD835 50%, #85D9F0 75%, #0087CD 100%)', // Мастер-бренд градиент
      button: 'linear-gradient(90deg, #21A038 0%, #0087CD 100%)',
      card: 'linear-gradient(135deg, rgba(33, 160, 56, 0.05) 0%, rgba(0, 135, 205, 0.05) 100%)'
    }
  },

  // Типографика
  typography: {
    fontFamily: '"SB Sans Display", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
    fontWeights: {
      light: 300,
      regular: 400,
      semibold: 600,
      bold: 700
    },
    fontSizes: {
      xs: '0.75rem',    // 12px
      sm: '0.875rem',   // 14px
      md: '1rem',       // 16px
      lg: '1.25rem',    // 20px
      xl: '1.5rem',     // 24px
      '2xl': '2rem',    // 32px
      '3xl': '2.5rem',  // 40px
      '4xl': '3rem',    // 48px
      '5xl': '3.75rem', // 60px
      '6xl': '4.5rem'   // 72px
    }
  },

  // Пространство
  spacing: {
    xs: '0.5rem',    // 8px
    sm: '0.75rem',   // 12px
    md: '1.5rem',    // 24px
    lg: '2rem',      // 32px
    xl: '4rem',      // 64px
    '2xl': '6rem',   // 96px
    '3xl': '8rem'    // 128px
  },

  // Радиусы границ
  borderRadius: {
    sm: '4px',
    md: '8px',
    lg: '12px',
    xl: '16px',
    circular: '50px',
    circle: '50%'
  },

  // Тени
  shadows: {
    sm: '0 2px 8px rgba(0, 0, 0, 0.05)',
    md: '0 4px 16px rgba(0, 0, 0, 0.08)',
    lg: '0 8px 24px rgba(0, 0, 0, 0.12)',
    focus: '0 0 0 3px rgba(33, 160, 56, 0.2)'
  },

  // Анимации
  animations: {
    fast: '150ms',
    normal: '300ms',
    slow: '500ms',
    curve: 'cubic-bezier(0.4, 0, 0.2, 1)'
  },

  // Медиа-запросы
  breakpoints: {
    xs: '320px',
    sm: '576px',
    md: '768px',
    lg: '992px',
    xl: '1200px',
    xxl: '1400px'
  }
};

export default theme; 