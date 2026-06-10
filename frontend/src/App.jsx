import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Dashboard from './pages/Dashboard';
import AlertsPage from './pages/AlertsPage';

function App() {
  return (
    <Router>
      <div className="App">
        <Routes>
          <Route path="/"       element={<Dashboard />} />
          <Route path="/alerts" element={<AlertsPage />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;