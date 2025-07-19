#!/bin/bash

# Master Script to set up Express TypeScript + React + shadcn/ui project
# Usage: ./master-setup-express-ts-react-shadcn.sh <project-name>
# Creates a full-stack app where Express serves the React frontend statically

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if project name is provided
if [ -z "$1" ]; then
    echo -e "${RED}❌ Error: Please provide a project name${NC}"
    echo -e "${YELLOW}Usage: ./master-setup-express-ts-react-shadcn.sh <project-name>${NC}"
    exit 1
fi

PROJECT_NAME=$1

echo -e "${GREEN}🚀 Setting up Express TypeScript + React + shadcn/ui project${NC}"
echo -e "${GREEN}📁 Project name: ${PROJECT_NAME}${NC}"

# Step 1: Create Express.js project
echo -e "${YELLOW}Step 1: Creating Express.js project...${NC}"
npx express-generator ${PROJECT_NAME}
cd ${PROJECT_NAME}

npm uninstall jade --save
# Step 2: Create controllers folder and indexController.js
echo -e "${YELLOW}Step 2: Setting up MVC structure...${NC}"
mkdir -p controllers

cat > controllers/indexController.js << 'EOF'
function index(req, res, next) {
    res.render('index', { title: 'Express' });
}

module.exports = {
    index
};
EOF

# Step 3: Update routes to use controller
echo -e "${YELLOW}Step 3: Updating routes to use controller pattern...${NC}"
cat > routes/index.js << 'EOF'
var express = require('express');
var router = express.Router();
var indexController = require('../controllers/indexController');

/* GET home page. */
router.get('/', indexController.index);

module.exports = router;
EOF

# Step 4: Install TypeScript dependencies
echo -e "${YELLOW}Step 4: Installing TypeScript dependencies...${NC}"
npm install --save-dev typescript @types/node @types/express @types/cookie-parser @types/morgan @types/http-errors @types/debug ts-node nodemon concurrently chokidar dotenv @types/dotenv

# Step 5: Generate random port and create .env file
echo -e "${YELLOW}Step 5: Creating .env file with random port...${NC}"
RANDOM_PORT=$((RANDOM % 9000 + 3000))
cat > .env << EOF
PORT=${RANDOM_PORT}
NODE_ENV=development
EOF

echo -e "${GREEN}📝 Generated random port: ${RANDOM_PORT}${NC}"

# Step 6: Create TypeScript configuration
echo -e "${YELLOW}Step 6: Creating TypeScript configuration...${NC}"
cat > tsconfig.json << 'EOF'
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "commonjs",
    "lib": ["ES2020"],
    "outDir": "./dist",
    "rootDir": "./",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true
  },
  "include": [
    "app.ts",
    "bin/**/*",
    "routes/**/*",
    "controllers/**/*"
  ],
  "exclude": [
    "node_modules",
    "client",
    "dist"
  ]
}
EOF

# Step 7: Convert JavaScript files to TypeScript
echo -e "${YELLOW}Step 7: Converting JavaScript files to TypeScript...${NC}"

# Convert indexController.js to TypeScript (API endpoint since we removed jade)
cat > controllers/indexController.ts << 'EOF'
import { Request, Response, NextFunction } from 'express';

function index(req: Request, res: Response, next: NextFunction): void {
    // Return JSON since we're serving React frontend and this is now an API endpoint
    res.json({
        message: 'Express TypeScript API Server',
        status: 'running',
        timestamp: new Date().toISOString()
    });
}

export default {
    index
};
EOF

# Convert routes/index.js to TypeScript
cat > routes/index.ts << 'EOF'
import express from 'express';
import indexController from '../controllers/indexController';

const router = express.Router();

/* GET home page. */
router.get('/', indexController.index);

export default router;
EOF

# Convert app.js to TypeScript with proper static serving
cat > app.ts << 'EOF'
import createError from 'http-errors';
import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import cookieParser from 'cookie-parser';
import logger from 'morgan';

import indexRouter from './routes/index';

const app = express();

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

// Serve static files from public directory
app.use(express.static(path.join(__dirname, 'public')));

// Step 8: Add code to statically serve the client frontend
// Serve React client build files statically from dist/client - this ensures the client is served from Express
app.use(express.static(path.join(__dirname, 'dist/client')));

// API routes (if any) should be defined before the catch-all
app.use('/api', indexRouter);

// Step 9: Catch-all handler to serve React app for client-side routing
// This ensures the client never runs its own server - everything goes through Express
app.get('*', (req: Request, res: Response) => {
  res.sendFile(path.join(__dirname, 'dist/client', 'index.html'));
});

// catch 404 and forward to error handler
app.use(function(req: Request, res: Response, next: NextFunction) {
  next(createError(404));
});

// error handler
app.use(function(err: any, req: Request, res: Response, next: NextFunction) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.json({ error: err.message });
});

export default app;
EOF

# Convert bin/www to TypeScript with .env support
cat > bin/www.ts << 'EOF'
#!/usr/bin/env node

/**
 * Module dependencies.
 */

import dotenv from 'dotenv';
import app from '../app';
import debugModule from 'debug';
import http from 'http';

// Load environment variables from .env file
dotenv.config();

const debug = debugModule('${PROJECT_NAME}:server');

/**
 * Get port from environment and store in Express.
 */

const port = normalizePort(process.env.PORT || '3333');
app.set('port', port);

/**
 * Create HTTP server.
 */

const server = http.createServer(app);

/**
 * Listen on provided port, on all network interfaces.
 */

server.listen(port);
server.on('error', onError);
server.on('listening', onListening);

/**
 * Normalize a port into a number, string, or false.
 */

function normalizePort(val: string): number | string | false {
  const port = parseInt(val, 10);

  if (isNaN(port)) {
    // named pipe
    return val;
  }

  if (port >= 0) {
    // port number
    return port;
  }

  return false;
}

/**
 * Event listener for HTTP server "error" event.
 */

function onError(error: NodeJS.ErrnoException): void {
  if (error.syscall !== 'listen') {
    throw error;
  }

  const bind = typeof port === 'string'
    ? 'Pipe ' + port
    : 'Port ' + port;

  // handle specific listen errors with friendly messages
  switch (error.code) {
    case 'EACCES':
      console.error(bind + ' requires elevated privileges');
      process.exit(1);
      break;
    case 'EADDRINUSE':
      console.error(bind + ' is already in use');
      process.exit(1);
      break;
    default:
      throw error;
  }
}

/**
 * Event listener for HTTP server "listening" event.
 */

function onListening(): void {
  const addr = server.address();
  const bind = typeof addr === 'string'
    ? 'pipe ' + addr
    : 'port ' + (addr?.port);
  debug('Listening on ' + bind);
}
EOF

# Step 8: Remove JavaScript files and jade references
echo -e "${YELLOW}Step 8: Cleaning up JavaScript files and jade references...${NC}"
rm -f app.js bin/www routes/index.js controllers/indexController.js
rm -rf views/ # Remove entire views directory since we're serving React frontend

# Step 9: Update package.json scripts with concurrent development
echo -e "${YELLOW}Step 9: Updating package.json scripts...${NC}"
# Create a new package.json with updated scripts including concurrent development
npm pkg set scripts.start="node ./dist/bin/www.js"
npm pkg set scripts.dev="concurrently \"npm run dev:server\" \"npm run dev:client\""
npm pkg set scripts.dev:server="nodemon --exec ts-node ./bin/www.ts --watch . --ext ts,js,json --ignore client/ --ignore node_modules/ --ignore dist/"
npm pkg set scripts.dev:client="chokidar \"client/src/**/*\" -c \"cd client && npm run build && echo 'Client rebuilt to dist/client/'\""
npm pkg set scripts.build="tsc"
npm pkg set scripts.clean="rm -rf dist"
npm pkg set scripts.build:client="cd client && npm run build"
npm pkg set scripts.build:all="npm run build:client && npm run build"
npm pkg set scripts.clean:all="rm -rf dist client/node_modules/.cache"

# Step 10: Create React client using the existing script logic
echo -e "${YELLOW}Step 10: Setting up React client with shadcn/ui...${NC}"

# Initialize create-react-app with TypeScript
npx create-react-app client --template typescript

# Remove git repository from client (we'll track the whole project as one repo)
rm -rf client/.git

# Navigate into the client directory
cd client

# Install dependencies
npm install --save tailwindcss@^3.4.0 postcss autoprefixer tailwindcss-animate class-variance-authority clsx tailwind-merge lucide-react

# Initialize Tailwind CSS
npx tailwindcss init -p

# Create tailwind.config.js
cat > tailwind.config.js << 'EOF'
const { fontFamily } = require("tailwindcss/defaultTheme");

/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: ["class"],
  content: ["./src/**/*.{js,jsx,ts,tsx}"],
  theme: {
    container: {
      center: true,
      padding: "2rem",
      screens: {
        "2xl": "1400px",
      },
    },
    extend: {
      colors: {
        border: "hsl(var(--border))",
        input: "hsl(var(--input))",
        ring: "hsl(var(--ring))",
        background: "hsl(var(--background))",
        foreground: "hsl(var(--foreground))",
        primary: {
          DEFAULT: "hsl(var(--primary))",
          foreground: "hsl(var(--primary-foreground))",
        },
        secondary: {
          DEFAULT: "hsl(var(--secondary))",
          foreground: "hsl(var(--secondary-foreground))",
        },
        destructive: {
          DEFAULT: "hsl(var(--destructive))",
          foreground: "hsl(var(--destructive-foreground))",
        },
        muted: {
          DEFAULT: "hsl(var(--muted))",
          foreground: "hsl(var(--muted-foreground))",
        },
        accent: {
          DEFAULT: "hsl(var(--accent))",
          foreground: "hsl(var(--accent-foreground))",
        },
        popover: {
          DEFAULT: "hsl(var(--popover))",
          foreground: "hsl(var(--popover-foreground))",
        },
        card: {
          DEFAULT: "hsl(var(--card))",
          foreground: "hsl(var(--card-foreground))",
        },
      },
      borderRadius: {
        lg: "var(--radius)",
        md: "calc(var(--radius) - 2px)",
        sm: "calc(var(--radius) - 4px)",
      },
      fontFamily: {
        sans: ["var(--font-sans)", ...fontFamily.sans],
      },
      keyframes: {
        "accordion-down": {
          from: { height: 0 },
          to: { height: "var(--radix-accordion-content-height)" },
        },
        "accordion-up": {
          from: { height: "var(--radix-accordion-content-height)" },
          to: { height: 0 },
        },
      },
      animation: {
        "accordion-down": "accordion-down 0.2s ease-out",
        "accordion-up": "accordion-up 0.2s ease-out",
      },
    },
  },
  plugins: [require("tailwindcss-animate")],
};
EOF

# Add CSS to src/index.css
cat > src/index.css << 'EOF'
@tailwind base;
@tailwind components;
@tailwind utilities;

@layer base {
  :root {
    --background: 0 0% 100%;
    --foreground: 222.2 47.4% 11.2%;

    --muted: 210 40% 96.1%;
    --muted-foreground: 215.4 16.3% 46.9%;

    --popover: 0 0% 100%;
    --popover-foreground: 222.2 47.4% 11.2%;

    --card: 0 0% 100%;
    --card-foreground: 222.2 47.4% 11.2%;

    --border: 214.3 31.8% 91.4%;
    --input: 214.3 31.8% 91.4%;

    --primary: 222.2 47.4% 11.2%;
    --primary-foreground: 210 40% 98%;

    --secondary: 210 40% 96.1%;
    --secondary-foreground: 222.2 47.4% 11.2%;

    --accent: 210 40% 96.1%;
    --accent-foreground: 222.2 47.4% 11.2%;

    --destructive: 0 100% 50%;
    --destructive-foreground: 210 40% 98%;

    --ring: 215 20.2% 65.1%;

    --radius: 0.5rem;
  }

  .dark {
    --background: 224 71% 4%;
    --foreground: 213 31% 91%;

    --muted: 223 47% 11%;
    --muted-foreground: 215.4 16.3% 56.9%;

    --popover: 224 71% 4%;
    --popover-foreground: 215 20.2% 65.1%;

    --card: 224 71% 4%;
    --card-foreground: 213 31% 91%;

    --border: 216 34% 17%;
    --input: 216 34% 17%;

    --primary: 210 40% 98%;
    --primary-foreground: 222.2 47.4% 1.2%;

    --secondary: 222.2 47.4% 11.2%;
    --secondary-foreground: 210 40% 98%;

    --accent: 216 34% 17%;
    --accent-foreground: 210 40% 98%;

    --destructive: 0 63% 31%;
    --destructive-foreground: 210 40% 98%;

    --ring: 216 34% 17%;

    --radius: 0.5rem;
  }
}

@layer base {
  * {
    @apply border-border;
  }
  body {
    @apply bg-background text-foreground;
    font-family: sans-serif;
  }
}
EOF

# Update tsconfig.json for client
cat > tsconfig.json << 'EOF'
{
  "compilerOptions": {
    "target": "es5",
    "lib": ["dom", "dom.iterable", "esnext"],
    "allowJs": true,
    "skipLibCheck": true,
    "esModuleInterop": true,
    "allowSyntheticDefaultImports": true,
    "strict": true,
    "forceConsistentCasingInFileNames": true,
    "noFallthroughCasesInSwitch": true,
    "module": "esnext",
    "moduleResolution": "node",
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noEmit": true,
    "jsx": "react-jsx",
    "baseUrl": ".",
    "paths": {
      "@/*": ["./src/*"]
    }
  },
  "include": [
    "src",
    "**/*.ts",
    "**/*.tsx"
  ]
}
EOF

# Create lib/utils.ts
mkdir -p src/lib
cat > src/lib/utils.ts << 'EOF'
import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}
EOF

# Create components.json for shadcn/ui
cat > components.json << 'EOF'
{
  "$schema": "https://ui.shadcn.com/schema.json",
  "style": "default",
  "rsc": false,
  "tsx": true,
  "tailwind": {
    "config": "tailwind.config.js",
    "css": "src/index.css",
    "baseColor": "slate",
    "cssVariables": true,
    "prefix": ""
  },
  "aliases": {
    "components": "src/components",
    "utils": "src/lib/utils"
  }
}
EOF

# Add shadcn/ui button component
npx shadcn@latest add button

# Update React build output directory to dist/client
npm pkg set homepage="."
npm pkg set scripts.build="BUILD_PATH=../dist/client react-scripts build"

# Delete App.css and update App.tsx
rm -f src/App.css

cat > src/App.tsx << 'EOF'
import { useState } from "react";
import { Button } from "./components/ui/button";
import logo from "./logo.svg";

function App() {
  const [count, setCount] = useState(0);
  return (
    <div className="App">
      <header className="h-screen flex flex-col items-center justify-center">
        <img
          src={logo}
          className="w-[40vmin] animate-[spin_10s_linear_infinite]"
          alt="logo"
        />
        <p>
          Edit <code>src/App.tsx</code> and save to reload.
        </p>
        <Button asChild variant="link">
          <a
            href="https://reactjs.org"
            target="_blank"
            rel="noopener noreferrer"
          >
            Learn React
          </a>
        </Button>
        <Button
          variant="outline"
          onClick={() => setCount((count) => count + 1)}
        >
          Count is {count}
        </Button>
                 <div className="mt-4 p-4 bg-green-100 rounded-lg">
           <p className="text-green-800 font-semibold">
             🎉 Full-stack app ready! Express TypeScript + React + shadcn/ui
           </p>
           <p className="text-green-600 text-sm">
             This React app is served statically by Express
           </p>
         </div>
      </header>
    </div>
  );
}

export default App;
EOF

# Step 11: Build client and return to project root
echo -e "${YELLOW}Step 11: Building React client...${NC}"
npm run build

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ React client build successful${NC}"
else
    echo -e "${RED}❌ React client build failed${NC}"
    exit 1
fi

cd ..

# Step 12: Build TypeScript server
echo -e "${YELLOW}Step 12: Building TypeScript server...${NC}"
npm run build

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ TypeScript server build successful${NC}"
else
    echo -e "${RED}❌ TypeScript server build failed${NC}"
    exit 1
fi

# Step 13: Open project in Cursor and provide instructions
echo -e "${GREEN}✅ Master setup complete! Your full-stack Express TypeScript + React + shadcn/ui project is ready.${NC}"
echo -e "${BLUE}📁 Project structure:${NC}"
echo -e "${BLUE}  ├── dist/                      # All build outputs${NC}"
echo -e "${BLUE}  │   ├── client/               # React build (served by Express)${NC}"
echo -e "${BLUE}  │   └── server files...       # Compiled TypeScript server${NC}"
echo -e "${BLUE}  ├── client/                   # React source code${NC}"
echo -e "${BLUE}  ├── controllers/, routes/     # Express TypeScript source${NC}"
echo -e "${BLUE}  ├── .env file with random port (${RANDOM_PORT})${NC}"
echo -e "${BLUE}  └── Concurrent development setup${NC}"
echo ""
echo -e "${YELLOW}📋 Features included:${NC}"
echo -e "${GREEN}  ✅ Express.js with TypeScript${NC}"
echo -e "${GREEN}  ✅ MVC architecture (controllers/routes)${NC}"
echo -e "${GREEN}  ✅ React with TypeScript${NC}"
echo -e "${GREEN}  ✅ shadcn/ui components${NC}"
echo -e "${GREEN}  ✅ Tailwind CSS${NC}"
echo -e "${GREEN}  ✅ Static serving from Express${NC}"
echo -e "${GREEN}  ✅ Single server architecture (no separate React server)${NC}"
echo -e "${GREEN}  ✅ Clean build organization (all outputs in dist/)${NC}"
echo -e "${GREEN}  ✅ Random port generation with .env support${NC}"
echo -e "${GREEN}  ✅ Concurrent development with file watching${NC}"
echo -e "${GREEN}  ✅ API endpoints on /api routes${NC}"
echo -e "${GREEN}  ✅ Client-side routing support with catch-all${NC}"
echo ""
echo -e "${YELLOW}🚀 Opening project in Cursor...${NC}"

# Open project in Cursor
echo -e "${BLUE}📝 Opening ${PROJECT_NAME} in Cursor...${NC}"

cd ${PROJECT_NAME}
cursor .

echo ""
echo -e "${GREEN}🎉 Your full-stack TypeScript application is ready!${NC}"
echo -e "${YELLOW}🌐 To start development server:${NC}"
echo -e "${GREEN}  cd ${PROJECT_NAME}${NC}"
echo -e "${GREEN}  npm run dev${NC}"
echo ""
echo -e "${YELLOW}📡 Your app will be available at: http://localhost:${RANDOM_PORT}${NC}"
echo -e "${YELLOW}📡 API endpoint will be: http://localhost:${RANDOM_PORT}/api${NC}"
echo ""
echo -e "${BLUE}💡 Development commands:${NC}"
echo -e "${GREEN}  npm run dev           # 🚀 Concurrent development (recommended)${NC}"
echo -e "${GREEN}  npm run dev:server    # Server only with TypeScript watching${NC}"
echo -e "${GREEN}  npm run dev:client    # Client build watch only${NC}"
echo -e "${GREEN}  npm run build:all     # Build both client and server${NC}"
echo -e "${GREEN}  npm start             # Start production server${NC}"
echo ""
echo -e "${YELLOW}🔧 Development features:${NC}"
echo -e "${GREEN}  • File watching for both frontend and backend${NC}"
echo -e "${GREEN}  • Automatic rebuild on changes${NC}"
echo -e "${GREEN}  • Hot reload for development${NC}"
echo -e "${GREEN}  • Random port (${RANDOM_PORT}) from .env file${NC}"
echo ""
echo -e "${BLUE}✨ Happy coding! Your project is now open in Cursor.${NC}"
echo -e "${BLUE}💻 Run 'npm run dev' to start development!${NC}"
