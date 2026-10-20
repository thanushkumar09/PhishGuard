# 🐋 Step 4.1: Establish Standard Virtual Node Framework Core Ecosystem Engine Base Image
FROM node:18-slim

# 🐍 Step 4.2: Install System Python Dependencies for Machine Learning Scikit Models Runtime Scripts
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*

# 📂 Establish Internal Production Application System Container Workspace Working Directory Mappings
WORKDIR /usr/src/app

# 📜 Copy Dependency Specifications Packaging Documents Profiles Targets
COPY package*.json ./
COPY requirements.txt ./

# 🛠️ Execute Core Applications Runtime Packages Installation Scripts Automation Commands
RUN npm ci
RUN pip3 install --no-cache-dir -r requirements.txt --break-system-packages

# 🚚 Copy Balance Internal Systems Complete Structural Code Workspace Repository Source Codes
COPY . .

# 🌐 Expose Enterprise API Systems Active Operational Container Network Local Host Port Target Mappings
EXPOSE 5000

# 🚦 Default Runtime Startup Bootstrap Commands Orchestrator For Isolated Container Instances
CMD ["npm", "start"]
