import tw from "tailwind-styled-components";
import { Link } from "react-router-dom";
import { ContainerEl } from "common-styles";

export const ExtendContainerEl = tw(ContainerEl)`
flex
justify-start
md:justify-between
items-center
`;



export const LinkContainerEl = tw.div`
flex
items-center
h-10
md:h-11
md:gap-x-8
`;

export const UserSettingsEl = tw.div`
hidden
md:flex
items-center
gap-x-8
h-11
text-sm
font-semibold
`;

export const UserNavLinkEl = tw(Link)`
text-nav-text-color
inline-flex
gap-2
items-center
`;

