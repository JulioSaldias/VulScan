FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY --chown=node:node . .
USER node
ENV NODE_ENV=production PORT=3000
EXPOSE 3000
CMD ["node", "server.js"]
