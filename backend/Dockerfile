FROM node:22-bookworm-slim AS benchmark

ENV NODE_ENV=development
WORKDIR /app

COPY --chown=node:node package.json package-lock.json ./
RUN npm ci

COPY --chown=node:node . .

USER node
CMD ["npm", "run", "benchmark"]

FROM node:22-bookworm-slim AS runtime

ENV NODE_ENV=production
WORKDIR /app

COPY --chown=node:node package.json package-lock.json ./
RUN npm ci --omit=dev

COPY --chown=node:node . .

USER node
EXPOSE 5000

# Run the package start script's Node command directly so SIGTERM reaches Node.
CMD ["node", "server.js"]
