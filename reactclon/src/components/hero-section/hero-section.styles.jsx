import tw from "tailwind-styled-components";

export const SliderContainerEl = tw.div`
w-full
relative
h-auto
md:h-[500px]
before:bg-gradient-to-r
before:from-primary-color
before:to-transparent
before:absolute
before:inset-0
before:z-10
`;

export const ImageEl = tw.img`
w-full
h-[500px]
object-cover
mix-blend-overlay 
`;

export const SliderContainerTextEl = tw.div`
md:container
flex
justify-between
items-center
relative
md:absolute
top-0
left-0
md:left-1/2
h-full
z-20
translate-x-0
md:-translate-x-1/2
`;

export const SloganEl = tw.h3`
mt-8
text-4xl
font-semibold
text-white
`;

export const SliderRegisterContainerEl = tw.div`
w-full
md:w-[400px]
md:rounded-lg
bg-gray-50 p-6
`;

export const RegisterOrLoginEl = tw.h4`
text-primary-color
text-center
font-semibold
mb-4
`;

export const InputRegisterOrLoginEl = tw.input`
text-sm
pt-2
h-14
px-4
border-2 
rounded
w-full
transition-colors
hover:border-primary-color
focus:border-primary-color
outline-none
peer 
`;

export const InputPlaceHolderEl = tw.span`
absolute 
top-0 
left-0 
text-gray-500
h-full
px-4
flex
items-center
text-sm
pointer-events-none
transition-all
peer-focus:h-7
peer-focus:text-xs
peer-focus:text-primary-color
peer-valid:h-7
peer-valid:text-xs
peer-valid:text-primary-color
`;


export const ButtonEl = tw.button`
bg-brand-yellow
h-12
flex
items-center
justify-center
rounded-md
w-full
text-sm
font-semibold
text-primary-color
hover:bg-primary-color
hover:text-brand-yellow
transition-colors
`;