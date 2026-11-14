FROM node:24-bookworm-slim
WORKDIR /app
COPY package*.json ./
RUN npm ci --ignore-scripts --omit=dev && mkdir -p /data && chown node:node /data
COPY --chown=node:node src ./src
COPY --chown=node:node migration ./migration
USER node
ENV NODE_ENV=production PORT=8080 IDENTITY_DATABASE=/data/identity.sqlite
EXPOSE 8080
CMD ["node","src/server.js"]
