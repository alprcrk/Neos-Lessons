import { BannerImgEl } from './banner.styles';

const Banner = ({ banner }) => {
  const { id, image } = banner;
  return <BannerImgEl src={image} />;
};

export default Banner;
