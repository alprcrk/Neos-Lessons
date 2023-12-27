import tw from "tailwind-styled-components";

export const CategoryContainerEl = tw.div`
flex
flex-col 
items-center
justify-center
hover:bg-primary-light
group
`;

export const ButtonEl = tw.button`
flex
flex-col
items-center
justify-center
w-[108px] h-[108px]
`;

export const ImgEl = tw.img`
border
border-gray-200
rounded-lg
w-12
h-12
`;

export const TitleEl = tw.div`
whitespace-nowrap
mt-3
font-semibold
text-sm
text-black
group-hover:text-primary-color
`
