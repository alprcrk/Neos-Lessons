import { ContainerEl } from "common-styles";
import { BsFillPersonFill } from "react-icons/bs";
import { ReactComponent as GetirLogo } from "assets/images/getir-active.svg";
import { ReactComponent as HomeLogo } from "assets/images/home.svg";
import { IoIosArrowForward } from "react-icons/io";
const MobileHeader = () => {
  return (
    <div className="md:hidden">
      <div className="bg-primary-color">
        <ContainerEl className="flex justify-between items-center relative px-3 h-16">
          <button>
            <BsFillPersonFill size="24" className="text-white" />
          </button>
          <a href="#" className="absolute left-1/2 -translate-x-1/2">
            <GetirLogo />
          </a>
        </ContainerEl>
      </div>
      <div className="h-10 container mx-auto bg-white">
        <button className="h-full w-full inline-flex justify-start items-center p-2 gap-x-2">
          <div>
            <HomeLogo width="16px" height="24px" />
          </div>
          <div className="font-semibold text-sm text-gray-800">Ev</div>
          <div className="font-semibold text-sm text-gray-500">Aliya Sok., No:6</div>
          <div className="ml-auto"><IoIosArrowForward className="text-gray-700"/></div>
        </button>
      </div>
    </div>
  );
};

export default MobileHeader;
