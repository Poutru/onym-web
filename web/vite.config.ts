import { defineConfig } from "vite";
export default defineConfig({
  server: {
    host: "127.0.0.1",
    proxy: {
      "/api/chain": "http://127.0.0.1:4173",
      "/preview/api/service-document": {
        target: "http://127.0.0.1:4173",
        rewrite: (p) => p.replace("/preview", ""),
      },
    },
  },
});
