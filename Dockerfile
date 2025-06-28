# Use Node.js LTS image
FROM node:20-alpine

# Create app directory and set as working directory
RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app

# Copy package files first for better caching
COPY package*.json ./

# Install dependencies
RUN npm i
# Copy the rest of the application
COPY . .

# Expose the app port
EXPOSE 4444

# Set the command to run the app
CMD ["node", "app.js"]