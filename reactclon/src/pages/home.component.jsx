import HeroSection from "../components/hero-section/hero-section.component";
import Categories from "../components/categories/categories.component";
import Campaigns from "../components/campaigns/campaigns-component";
import MobileApp from "../components/mobile-app/mobile-app.component";
import Cards from "../components/cards/cards.component";
import Footer from "../components/footer/footer.component";
import {WindowWithContext} from "contexts/window-with.context";
import {useContext} from "react";


const Home = () => {
  const windowWith = useContext(WindowWithContext);
  return (
    <>
      {windowWith < 751 && <Campaigns />}
      <HeroSection />
      <Categories />
      {windowWith >= 751 && <Campaigns />}
      <MobileApp />
      <Cards />
      <Footer />
    </>
  );
};

export default Home;
