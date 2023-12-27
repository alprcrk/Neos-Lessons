/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
  ],
  theme: {
    screens: {
      sm: '640px',
      md: '768px',
      lg: '1024px',
      xl: '1280px',
    },
    extend: {
      backgroundImage : theme => ({
        "mobile-app-background" : "url('https://cdn.getir.com/getirweb-images/common/illustration/doodle.png')"
      }) ,
      colors: {
        "brand-color": "#4c3398",
        "nav-text-color": "#dbdbff",
        "primary-color": "#5d3ebc",
        "secondary-color": "#7849f7",
        "brand-yellow": "#ffd300",
        "black": "#191919",
        "primary-light": "#f3f0fe"
      },
    },
  },
  plugins: [],
}


//Main page register input label color #838287