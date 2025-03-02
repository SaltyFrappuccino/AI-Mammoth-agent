import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { ThemeProvider } from 'styled-components';
import theme from './styles/theme';

// Импорт компонентов
import Navbar from './components/Navbar';
import Footer from './components/Footer';

// Импорт страниц
import HomePage from './pages/HomePage';
import AnalyzePage from './pages/AnalyzePage';
import ResultsPage from './pages/ResultsPage';
import DocumentationPage from './pages/DocumentationPage';

// Компонент для визуализации (заглушка, будет реализован позже)
const VisualizationPage = () => (
  <div style={{ padding: '50px', textAlign: 'center' }}>
    <h1>Визуализация</h1>
    <p>Эта страница будет отображать визуализацию результатов анализа.</p>
  </div>
);

// Компонент для страницы условий использования
const TermsPage = () => (
  <div style={{ padding: '50px', textAlign: 'center' }}>
    <h1>Условия использования</h1>
    <p>Здесь будут размещены условия использования сервиса.</p>
  </div>
);

// Компонент для страницы политики конфиденциальности
const PrivacyPage = () => (
  <div style={{ padding: '50px', textAlign: 'center' }}>
    <h1>Политика конфиденциальности</h1>
    <p>Здесь будет размещена политика конфиденциальности сервиса.</p>
  </div>
);

// Компонент для страницы 404
const NotFoundPage = () => (
  <div style={{ padding: '50px', textAlign: 'center' }}>
    <h1>404 - Страница не найдена</h1>
    <p>Запрашиваемая страница не существует.</p>
  </div>
);

function App() {
  return (
    <ThemeProvider theme={theme}>
      <Router>
        <Navbar appName="AI-Mammoth" />
        <main>
          <Routes>
            <Route path="/" element={<HomePage />} />
            <Route path="/analyze" element={<AnalyzePage />} />
            <Route path="/results" element={<ResultsPage />} />
            <Route path="/visualization" element={<VisualizationPage />} />
            <Route path="/terms" element={<TermsPage />} />
            <Route path="/privacy" element={<PrivacyPage />} />
            <Route path="/documentation" element={<DocumentationPage />} />
            <Route path="*" element={<NotFoundPage />} />
          </Routes>
        </main>
        <Footer />
      </Router>
    </ThemeProvider>
  );
}

export default App;
