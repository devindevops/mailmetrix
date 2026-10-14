FROM node:alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY src ./src

CMD ["node", "--watch", "src/server.js"]
