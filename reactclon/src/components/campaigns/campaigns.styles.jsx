import tw from "tailwind-styled-components";
import Slider from "react-slick";
import styled from "styled-components";

export const SliderEl = tw(Slider)`
  -mx-5
  
  `;

export const BannerContainerEl = tw.div`
  px-5 
  ${({isMouseDown}) => isMouseDown ? 'cursor-grabbing'  : 'cursor-grab'}
  `;
