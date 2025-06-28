# Use Node.js LTS image
FROM node:20-alpine

# Create app directory
WORKDIR /usr/src/app

# Copy package files
COPY package*.json ./

# Install production dependencies only
RUN npm ci

# Bundle app source
COPY . .

# Verify files are in place
RUN ls -la /usr/src/app/ && [ -f /usr/src/app/package.json ]

# Expose the app port
EXPOSE 4444

# Set the command to run the app
CMD ["node", "app.js"]