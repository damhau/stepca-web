/** @type {import("prettier").Config} */
export default {
  semi: false,
  printWidth: 120,
  plugins: ["prettier-plugin-tailwindcss"],
  tailwindStylesheet: "./src/index.css",
}
