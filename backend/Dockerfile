FROM node:alpine

WORKDIR /app

# Update Alpine packages, then remove package-index/cache files in the same layer.
RUN apk update && apk upgrade && rm -rf /var/cache/apk/*

COPY package*.json ./
RUN npm ci

COPY src ./src

CMD ["node", "--watch", "src/server.js"]
