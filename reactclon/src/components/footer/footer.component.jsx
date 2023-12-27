import { ContainerEl } from "common-styles";
import Menu from "components/menu/menu.component";
import { ReactComponent as AppStoreLogo } from "assets/images/app-store.svg";
import { ReactComponent as GooglePlayLogo } from "assets/images/google-play.svg";
import { ReactComponent as AppGalleryLogo } from "assets/images/app-gallery.svg";
import { FaFacebook, FaTwitter, FaInstagram } from "react-icons/fa";
import { RiGlobalLine } from "react-icons/ri";

const menus = [
  {
    title: "Getir'i keşfedin",
    items: [
      {
        subtitle: "Hakkımızda",
      },
      {
        subtitle: "Kariyer",
      },
      {
        subtitle: "Teknoloji Kariyerleri",
      },
      {
        subtitle: "İletişim",
      },
      {
        subtitle: "Sosyal Sorumluluk Projeleri",
      },
    ],
  },
  {
    title: "Yardıma mı ihtiyacınız var?",
    items: [
      {
        subtitle: "Hakkımızda",
      },
      {
        subtitle: "Kariyer",
      },
      {
        subtitle: "Teknoloji Kariyerleri",
      },
      {
        subtitle: "İletişim",
      },
      {
        subtitle: "Sosyal Sorumluluk Projeleri",
      },
    ],
  },
  {
    title: "İş Ortağımız Olun",
    items: [
      {
        subtitle: "Hakkımızda",
      },
      {
        subtitle: "Kariyer",
      },
      {
        subtitle: "Teknoloji Kariyerleri",
      },
      {
        subtitle: "İletişim",
      },
      {
        subtitle: "Sosyal Sorumluluk Projeleri",
      },
    ],
  },
];

const Footer = () => {
  return (
    <div className="bg-white mt-5">
      <ContainerEl className="px-4 md:px-0">
        <div className="grid gap-y-6 md:grid-cols-4 gap-x-6 pt-5 md:pt-10">
          <section>
            <nav className="grid gap-y-4">
              <h6 className="text-lg text-primary-color">Getir'i indirin!</h6>
              <AppStoreLogo />
              <GooglePlayLogo />
              <AppGalleryLogo />
            </nav>
          </section>
          {menus.map((menu, index) => (
            <Menu key={index + 1} menu={menu} /> 
          ))}
        </div>
        <div className="flex flex-col md:flex-row gap-y-4 md:gap-y-0 justify-between items-center border-t border-gray-200 mt-6 py-6">
          <div className="text-xs text-gray-700 flex gap-x-8">
            &copy; 2023 Getir Clone Alper
            <a
              className="text-primary-color before:absolute before:w-1 before:h-1 before:rounded-[50%] relative  before:bg-primary-color before:-left-5 before:top-1/2 before:-translate-y-1/2 "
              href="#"
            >
              Bilgi Toplumu Hizmetleri
            </a>
          </div>
          <nav className="flex gap-x-3">
            <a href="#" className="w-8 h-8 rounded-lg text-gray-500 transition-colors hover:bg-primary-color hover:bg-opacity-10 hover:text-primary-color flex items-center justify-center">
              <FaFacebook size={20} />
            </a>
            <a href="#" className="w-8 h-8 rounded-lg text-gray-500 transition-colors hover:bg-primary-color hover:bg-opacity-10 hover:text-primary-color flex items-center justify-center">
              <FaTwitter size={20} />
            </a>
            <a href="#" className="w-8 h-8 rounded-lg text-gray-500 transition-colors hover:bg-primary-color hover:bg-opacity-10 hover:text-primary-color flex items-center justify-center">
              <FaInstagram size={20} />
            </a>
            <a href="#" className="h-8 flex items-center px-2 border border-gray-100 text-sm gap-x-2 rounded text-gray-500 hover:border-transparent  hover:bg-primary-color hover:text-primary-color hover:bg-opacity-10 transition-colors">
            <RiGlobalLine size={20}/>
            Türkçe (TR)
            </a>
          </nav>
        </div>
      </ContainerEl>
    </div>
  );
};

export default Footer;
