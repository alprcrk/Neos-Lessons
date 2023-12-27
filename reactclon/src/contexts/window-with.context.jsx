import { createContext } from "react";
import { useWindowWidth } from "@react-hook/window-size";

export const WindowWithContext = createContext();
export const WindowWithProvider = ({ children }) => {
  const windowWith = useWindowWidth();

  return <WindowWithContext.Provider value={windowWith}>{children}</WindowWithContext.Provider>;
};
