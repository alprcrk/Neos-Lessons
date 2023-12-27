import { useState, useContext, useEffect } from "react";
import { Collapse } from "react-collapse";
import { WindowWithContext } from "contexts/window-with.context";
import { IoIosArrowDown } from "react-icons/io";

const Menu = ({ menu }) => {
  const { title, items } = menu;
  const windowWith = useContext(WindowWithContext);
  const [isOpen, setIsOpen] = useState(windowWith >= 751);

  const toggleCollapse = () => {
    if (windowWith < 751) {
      setIsOpen(!isOpen);
    }
  };

  useEffect(() => {
    if (windowWith < 751) {
      setIsOpen(false);
    } else {
      setIsOpen(true);
    }
  }, [windowWith]);
  return (
    <section>
      <nav className="grid gap-y-2 md:gap-y-4">
        <h6
          onClick={toggleCollapse}
          className="text-lg text-primary-color flex items-center justify-between"
        >
          {title}
          <button className="w-6 h-6 rounded-lg flex items-center justify-center bg-primary-color bg-opacity-10 text-primary-color md:hidden">
            <span className={`transition-transform ${isOpen ? "transform rotate-180" : ""}`}>
              <IoIosArrowDown size={15} />
            </span>
          </button>
        </h6>
        <Collapse isOpened={isOpen}>
          <nav>
            <ul className="grid gap-y-1 md:gap-y-2">
              {items.map((item, index) => (
                <li key={index + 1}>
                  <a className="text-sm" href="#">
                    {item.subtitle}
                  </a>
                </li>
              ))}
            </ul>
          </nav>
        </Collapse>
      </nav>
    </section>
  );
};

export default Menu;
