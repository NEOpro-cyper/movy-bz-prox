# Use the official Node.js 20 image (LTS)
FROM node:20-alpine

# Set the working directory inside the container
WORKDIR /app

# Copy package.json and install dependencies
COPY package.json ./
RUN npm install --production

# Copy the rest of the application code
COPY server.js ./

# Expose the port the app runs on
EXPOSE 3000

# Command to start the app
CMD ["node", "server.js"]
