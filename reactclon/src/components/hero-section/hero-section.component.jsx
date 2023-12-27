import { ReactComponent as GetirMutlulukLogo } from "assets/images/getir-mutluluk.svg";
import {
  SliderContainerEl,
  ImageEl,
  SliderContainerTextEl,
  SloganEl,
  SliderRegisterContainerEl,
  RegisterOrLoginEl,
  InputRegisterOrLoginEl,
  InputPlaceHolderEl,
  ButtonEl,
} from "./hero-section.styles";
import { useWindowWidth } from "@react-hook/window-size";
import React, { useState } from "react";

import Slider from "react-slick";
import "slick-carousel/slick/slick.css";
import "slick-carousel/slick/slick-theme.css";
import ReactFlagsSelect from "react-flags-select";

const HeroSection = () => {
  const windowWith = useWindowWidth();
  const [selected, setSelected] = useState("TR");
  const phones = {
    US: "+1",
    DE: "+50",
    TR: "+90",
    IT: "+7",
    IN: "+15",
  };
  const settings = {
    infinite: true,
    slidesToShow: 1,
    slidesToScroll: 1,
    autoplay: true,
    swipe: false,
    speed: 500,
    autoplaySpeed: 5000,
    arrows: false,
  };
  console.log(windowWith);
  return (
    <SliderContainerEl>
      {windowWith >= 751 && (
        <Slider {...settings}>
          <div>
            <ImageEl src="https://cdn.getir.com/getirweb-images/common/hero-posters/getir-mainpage-4.jpg" />
          </div>

          <div>
            <ImageEl src="https://cdn.getir.com/getirweb-images/common/hero-posters/getir-mainpage-1.jpg" />
          </div>
        </Slider>
      )}
      <SliderContainerTextEl>
        <div className="hidden md:block">
          <GetirMutlulukLogo width="180px" height="180px" />
          <SloganEl>
            Dakikalar içinde <br /> kapınızda
          </SloganEl>
        </div>
        <SliderRegisterContainerEl>
          <RegisterOrLoginEl>Giriş yap veya kayıt ol</RegisterOrLoginEl>
          <div className="grid flex-col gap-y-3">
            <div className="flex gap-x-2">
              <ReactFlagsSelect
                countries={Object.keys(phones)}
                customLabels={phones}
                onSelect={(code) => setSelected(code)}
                selected={selected}
                className="flag-select  w-[110px]"
              />
              <label className="flex-1 relative block">
                <InputRegisterOrLoginEl required />
                <InputPlaceHolderEl>Telefon Numarası</InputPlaceHolderEl>
              </label>
            </div>
            <ButtonEl>Telefon numarası ile devam et</ButtonEl>
          </div>
        </SliderRegisterContainerEl>
      </SliderContainerTextEl>
    </SliderContainerEl>
  );
};

export default HeroSection;
