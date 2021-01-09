# Build stage
FROM node:10-alpine as builder

COPY package*.json ./

RUN npm install

# Second stage
FROM node:10-alpine

WORKDIR /usr/src/app
COPY --from=builder node_modules node_modules
COPY . .

CMD [ "npm", "run", "dev" ]