# ---------------------------------------------------------------------------
# 前端镜像 —— 两阶段:node 构建,nginx 只带产物。
# 最终镜像里没有 node_modules,也没有源码。
# ---------------------------------------------------------------------------
FROM node:22-alpine AS build

WORKDIR /app
COPY package.json package-lock.json* ./
# esbuild 的 postinstall 要跑(装二进制),所以不能用 --ignore-scripts
RUN npm ci 2>/dev/null || npm install

COPY . .
# 构建时不跑 vue-tsc —— 类型检查是 CI 的事,放在镜像构建里会让
# 一个类型警告卡住整条部署流水线
RUN npx vite build

FROM nginx:1.27-alpine

ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
