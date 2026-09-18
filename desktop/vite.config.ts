import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
  },
  plugins: [react()],
});
