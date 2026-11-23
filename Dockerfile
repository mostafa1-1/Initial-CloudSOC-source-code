# Local demonstration container only. Do not expose publicly with seeded demo passwords.
FROM node:22-bookworm-slim
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --include=dev --no-audit --no-fund
COPY . .
RUN npm run lint && npm run build
ENV NODE_ENV=production
ENV PORT=3000
ENV DATABASE_PATH=/app/data/cloudsoc.db
RUN mkdir -p /app/data
EXPOSE 3000
CMD ["npm", "run", "start"]
