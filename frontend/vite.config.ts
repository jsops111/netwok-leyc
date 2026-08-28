import { fileURLToPath, URL } from 'node:url'
import vue from '@vitejs/plugin-vue'
import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  server: {
    // 5273 —— 隔壁 ops-ai-cmdb 的 dev server 用 5173,别撞
    port: 5273,
    host: '127.0.0.1',
    proxy: {
      // 后端在 8100(隔壁 gunicorn 占了 8000)
      '/api': { target: 'http://127.0.0.1:8100', changeOrigin: true },
    },
  },
  build: {
    outDir: 'dist',
    chunkSizeWarningLimit: 1200,
    rollupOptions: {
      output: {
        manualChunks: {
          // echarts 单独切出来 —— 它比业务代码大好几倍,分开之后
          // 改业务代码不会让用户重新下载图表库
          echarts: ['echarts'],
          naive: ['naive-ui'],
        },
      },
    },
  },
})
