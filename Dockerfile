# GESP C++ 云端编译服务镜像（Linux g++，仅暴露 /ping /run）
FROM node:20-slim

# 安装 g++（GESP 三级按 C++11 标准，本镜像 g++ 12 默认支持 c++11/14/17）
RUN apt-get update \
  && apt-get install -y --no-install-recommends g++ \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY compile-server.js .

# 云端模式开关：监听 $PORT（平台自动注入），Linux g++, 只暴露 API
ENV CLOUD=1

EXPOSE 3000
CMD ["node", "compile-server.js"]
