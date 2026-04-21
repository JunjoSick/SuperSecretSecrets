import { createBrowserRouter } from 'react-router-dom';
import App from './App';
import Landing from './pages/Landing';
import Encode from './pages/Encode';
import Recover from './pages/Recover';
import About from './pages/About';

// Strip trailing slash so "/foo/" becomes "/foo" (React Router convention).
const basename = import.meta.env.BASE_URL.replace(/\/$/, '') || '/';

export const router = createBrowserRouter(
  [
    {
      path: '/',
      element: <App />,
      children: [
        { index: true, element: <Landing /> },
        { path: 'encode', element: <Encode /> },
        { path: 'recover', element: <Recover /> },
        { path: 'about', element: <About /> },
      ],
    },
  ],
  { basename },
);
