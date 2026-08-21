FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
# Baked in at build time (Vite only reads import.meta.env at build) -- empty
# string, not unset, so the frontend's `?? 'http://127.0.0.1:8000'` fallback
# doesn't kick in and fetches stay same-origin (/api/... on invariant.victordg.dev.br).
ARG VITE_API_BASE=""
ENV VITE_API_BASE=$VITE_API_BASE
RUN npm run build

FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
