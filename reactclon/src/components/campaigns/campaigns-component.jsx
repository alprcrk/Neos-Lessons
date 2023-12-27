import Banner from "components/banner/banner.component";
import bannerDatas from "api/banners.json";
import { SliderEl, BannerContainerEl} from "./campaigns.styles";
import { TitleEl } from "common-styles";
import { useState, useEffect } from "react";

const Campaigns = () => {
  const [banners, setBanners] = useState([]);
  const [isMouseDown, setIsMouseDown] = useState(false);

  useEffect(() => {
    setBanners(bannerDatas);
  }, []);

  const handleMouseEvent = (e) => {
    const flag = e.type === "mousedown" ? true : false;
    setIsMouseDown(flag);
  };

  const settings = {
    infinite: true,
    slidesToShow: 3,
    slidesToScroll: 2,
    autoplay: true,
    swipe: true,
    speed: 500,
    autoplaySpeed: 3000,
    arrows: false,
    responsive: [
      {
        breakpoint: 1024,
        settings: {
          slidesToShow: 2,
          slidesToScroll: 2,
          infinite: true,
          dots: false
        }
      },
      {
        breakpoint: 768,
        settings: {
          slidesToShow: 1,
          slidesToScroll: 1,
          infinite: true,
          dots: false
        }
      },
    ]
  };
  return (
    <div className="md:container md:mx-auto md:py-8 overflow-x-hidden">
      <TitleEl className="hidden md:block">Kampanyalar</TitleEl>
      <SliderEl {...settings}>
        {banners &&
          banners.map((banner) => (
            <BannerContainerEl
              key={banner.id}
              isMouseDown={isMouseDown}
              onMouseDown={handleMouseEvent}
              onMouseUp={handleMouseEvent}
            >
              <Banner banner={banner} />
            </BannerContainerEl>
          ))}
      </SliderEl>
    </div>
  );
};

export default Campaigns;
