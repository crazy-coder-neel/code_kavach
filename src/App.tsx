import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { LandingPage } from './pages/LandingPage';
import { AppShell } from './components/layout/AppShell';
import { ScanPage } from './pages/ScanPage';
import { BatchPage } from './pages/BatchPage';
import { HistoryPage } from './pages/HistoryPage';
import { AnalyticsPage } from './pages/AnalyticsPage';
import { ResponsibleAIPage } from './pages/ResponsibleAIPage';
import { RulesPage } from './pages/RulesPage';
import { PlaygroundPage } from './pages/PlaygroundPage';
import { IntegrationsPage } from './pages/IntegrationsPage';
import { SettingsPage } from './pages/SettingsPage';

import { ThemeProvider } from './lib/theme/ThemeContext';

export function App() {
  return (
    <ThemeProvider>
      <BrowserRouter>
        <Routes>
          {/* Landing Page */}
          <Route path="/" element={<LandingPage />} />

          {/* Application Workspace Routes */}
          <Route path="/app" element={<AppShell />}>
            <Route index element={<Navigate to="/app/scan" replace />} />
            <Route path="scan" element={<ScanPage />} />
            <Route path="batch" element={<BatchPage />} />
            <Route path="history" element={<HistoryPage />} />
            <Route path="analytics" element={<AnalyticsPage />} />
            <Route path="rules" element={<RulesPage />} />
            <Route path="playground" element={<PlaygroundPage />} />
            <Route path="integrations" element={<IntegrationsPage />} />
            <Route path="responsible-ai" element={<ResponsibleAIPage />} />
            <Route path="settings" element={<SettingsPage />} />
          </Route>

          {/* Catch-all */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </ThemeProvider>
  );
}

export default App;
