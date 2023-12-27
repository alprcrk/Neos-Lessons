import { Routes, Route } from "react-router-dom"
import Header from "./components/header/header-component";
import Home from './pages/home.component';
import GetirBuyukPage from "./pages/getir-buyuk.component";
import GetirYemekPage from "pages/getir-yemek.component";
import GetirSuPage from "pages/getir-su.component";
import { WindowWithProvider } from "contexts/window-with.context";



function App() {
  return (
    <WindowWithProvider>
      <Routes>
        <Route path="/" element={<Header />}>
          <Route index element={<Home />} />
          <Route path="buyuk" element={<GetirBuyukPage />} />
          <Route path="yemek" element={<GetirYemekPage />} />
          <Route path="su" element={<GetirSuPage />} />
        </Route>
      </Routes>
    </WindowWithProvider>
  );
}

export default App;
