/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./templates/*",
     "./node_modules/tw-elements/js/**/*.js"
  ],
  theme: {
    extend: {
      backgroundImage: {
        'home': "url('assets/food.jpg')",
      },
       fontFamily: {
         poppins: ["Poppins", "sans-serif"],
         julius: ["Julius Sans One", "sans-serif"],
         dev:[""]
      },
       screens: {
      'xs':'340px',
    },
       
    },
  },
  plugins:  [require("tw-elements/plugin.cjs")],
  darkMode: "class",
}



