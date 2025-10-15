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
npm install --save-dev typescript @types/node @types/express @types/cookie-parser @types/morgan @types/http-errors @types/debug ts-node nodemon concurrently chokidar-cli dotenv @types/dotenv

# Step 5: Generate random port and create .env file
echo -e "${YELLOW}Step 5: Creating .env file with random port...${NC}"
RANDOM_PORT=$((RANDOM % 9000 + 3000))
cat > .env << EOF
PORT=${RANDOM_PORT}
NODE_ENV=development
EOF

echo -e "${GREEN}📝 Generated random port: ${RANDOM_PORT}${NC}"

# Step 5.1: Create comprehensive .gitignore file
echo -e "${YELLOW}Step 5.1: Creating .gitignore file...${NC}"
cat > .gitignore << 'EOF'
# Dependencies
node_modules/
client/node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*
lerna-debug.log*

# Build outputs
dist/
build/
client/build/

# Environment variables
.env
.env.local
.env.development.local
.env.test.local
.env.production.local

# Runtime data
pids
*.pid
*.seed
*.pid.lock

# Coverage directory used by tools like istanbul
coverage/
*.lcov

# Dependency directories
jspm_packages/

# TypeScript cache
*.tsbuildinfo

# Optional npm cache directory
.npm

# Optional eslint cache
.eslintcache

# Microbundle cache
.rpt2_cache/
.rts2_cache_cjs/
.rts2_cache_es/
.rts2_cache_umd/

# Optional REPL history
.node_repl_history

# Output of 'npm pack'
*.tgz

# Yarn Integrity file
.yarn-integrity

# parcel-bundler cache (https://parceljs.org/)
.cache
.parcel-cache

# Next.js build output
.next

# Nuxt.js build / generate output
.nuxt

# Gatsby files
.cache/
public

# Storybook build outputs
.out
.storybook-out

# Temporary folders
tmp/
temp/

# Editor directories and files
.vscode/
.idea/
*.swp
*.swo
*~

# OS generated files
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db

# Logs
logs
*.log

# Runtime data
pids
*.pid
*.seed
*.pid.lock

# Optional npm cache directory
.npm

# Optional REPL history
.node_repl_history

# Output of 'npm pack'
*.tgz

# Yarn Integrity file
.yarn-integrity

# dotenv environment variables file
.env

# Production build
/build

# misc
.DS_Store
.env.local
.env.development.local
.env.test.local
.env.production.local

npm-debug.log*
yarn-debug.log*
yarn-error.log*
EOF

echo -e "${GREEN}✅ .gitignore file created${NC}"

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
cat > controllers/indexController.ts << EOF
import { Request, Response, NextFunction } from 'express';

function index(req: Request, res: Response, next: NextFunction): void {
    // Return JSON since we're serving React frontend and this is now an API endpoint
    res.json({
        message: '${PROJECT_NAME} API Server',
        description: 'Express TypeScript API Server',
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

import 'dotenv/config';
import app from '../app';
import debugModule from 'debug';
import http from 'http';

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
  if (typeof addr === 'string') {
    console.log(`server started:  http://localhost:${addr}`);
  } else {
    console.log(`server started:  http://localhost:${addr?.port}`);
  }
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

# === Auth/RBAC setup (embedded, gated) ===
# Feature gate (default ON unless explicitly disabled)
if [ -z "${ENABLE_AUTH_RBAC+x}" ]; then
    ENABLE_AUTH_RBAC=1
fi

mkdir -p .appstarter

if [ "$ENABLE_AUTH_RBAC" != "1" ]; then
    echo -e "${YELLOW}Auth/RBAC setup skipped (ENABLE_AUTH_RBAC=${ENABLE_AUTH_RBAC}).${NC}"
else
    echo -e "${YELLOW}Auth/RBAC: Installing ORM/auth/session dependencies...${NC}"
    npm install --save sequelize sequelize-cli sqlite3 pg pg-hstore passport passport-local passport-jwt bcrypt jsonwebtoken cors express-session connect-session-sequelize dotenv
    npm install --save-dev @types/express-session @types/bcrypt @types/jsonwebtoken @types/cors @types/passport @types/passport-local @types/passport-jwt

    echo -e "${YELLOW}Auth/RBAC: Installing hardening dependencies (zod, helmet, rate-limit, nodemailer)...${NC}"
    npm install --save zod helmet express-rate-limit nodemailer
    npm install --save-dev @types/helmet @types/nodemailer

    echo -e "${YELLOW}Auth/RBAC: Writing Sequelize CLI configuration...${NC}"
    # .sequelizerc to point CLI to our config and folders
    cat > .sequelizerc << 'EOF'
const path = require('path');

module.exports = {
  config: path.resolve('db', 'config.cjs'),
  'migrations-path': path.resolve('db', 'migrations'),
  'seeders-path': path.resolve('db', 'seeders'),
  'models-path': path.resolve('models')
};
EOF

    # Ensure required directories exist
    mkdir -p db/migrations db/seeders var

    # Sequelize environment config (dev=test sqlite, prod postgres via DATABASE_URL)
    cat > db/config.cjs << 'EOF'
/**
 * Sequelize CLI configuration for different environments.
 * Dev/Test use SQLite with storage from SQLITE_STORAGE, Prod uses DATABASE_URL (Postgres).
 */
module.exports = {
  development: {
    dialect: 'sqlite',
    storage: process.env.SQLITE_STORAGE || './var/dev.sqlite',
    logging: false,
  },
  test: {
    dialect: 'sqlite',
    storage: process.env.SQLITE_STORAGE || ':memory:',
    logging: false,
  },
  production: {
    use_env_variable: 'DATABASE_URL',
    dialect: 'postgres',
    protocol: 'postgres',
    logging: false,
    dialectOptions: {
      ssl: process.env.PGSSL === '0' ? false : { require: true, rejectUnauthorized: false },
    },
  },
};
EOF

    echo -e "${YELLOW}Auth/RBAC: Ensuring .env contains required secrets and settings...${NC}"
    # Ensure .env exists
    if [ ! -f .env ]; then
        cat > .env << EOF
PORT=${RANDOM_PORT}
NODE_ENV=development
EOF
    fi

    # Helper to append key=value if key not present
    ensure_env() {
        local key="$1"; local value="$2"
        if ! grep -q "^${key}=" .env 2>/dev/null; then
            echo "${key}=${value}" >> .env
        fi
    }

    # Generate secrets if missing
    SESSION_SECRET_VALUE=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))" 2>/dev/null)
    JWT_SECRET_VALUE=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))" 2>/dev/null)

    ensure_env "SQLITE_STORAGE" "./var/dev.sqlite"
    ensure_env "SESSION_SECRET" "${SESSION_SECRET_VALUE:-change-me-session}"
    ensure_env "JWT_SECRET" "${JWT_SECRET_VALUE:-change-me-jwt}"
    ensure_env "JWT_ACCESS_TTL" "15m"
    ensure_env "JWT_REFRESH_TTL" "7d"
    ensure_env "PUBLIC_BASE_URL" "http://localhost:${RANDOM_PORT}"
    ensure_env "CLIENT_ORIGINS" "http://localhost:${RANDOM_PORT}"
    ensure_env "RATE_LIMIT_WINDOW_MS" "60000"
    ensure_env "RATE_LIMIT_MAX" "100"
    ensure_env "SMTP_HOST" ""
    ensure_env "SMTP_PORT" "587"
    ensure_env "SMTP_USER" ""
    ensure_env "SMTP_PASS" ""
    ensure_env "SMTP_FROM" ""

    echo -e "${YELLOW}Auth/RBAC: Adding npm database scripts...${NC}"
    npm pkg set scripts.db:migrate="sequelize-cli db:migrate"
    npm pkg set scripts.db:migrate:undo="sequelize-cli db:migrate:undo"
    npm pkg set scripts.db:seed="sequelize-cli db:seed:all"
    npm pkg set scripts.db:reset="sequelize-cli db:migrate:undo:all && sequelize-cli db:migrate && sequelize-cli db:seed:all"

    # Mark bootstrap completion
    if [ ! -f .appstarter/.auth_rbac_bootstrap_done ]; then
        echo "bootstrapped" > .appstarter/.auth_rbac_bootstrap_done
    fi

    echo -e "${YELLOW}Auth/RBAC: Scaffolding TypeScript DB init and models...${NC}"

    mkdir -p db models auth middleware

    # Update tsconfig.json include globs to compile new folders
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
    "controllers/**/*",
    "models/**/*",
    "db/**/*",
    "auth/**/*",
    "middleware/**/*"
  ],
  "exclude": [
    "node_modules",
    "client",
    "dist"
  ]
}
EOF

    # DB init using Sequelize (SQLite dev, Postgres prod)
    cat > db/sequelize.ts << 'EOF'
import { Sequelize } from 'sequelize';

const isProduction = process.env.NODE_ENV === 'production';

let sequelize: Sequelize;
const databaseUrl = process.env.DATABASE_URL as string | undefined;
if (isProduction && databaseUrl) {
  sequelize = new Sequelize(databaseUrl, {
    dialect: 'postgres',
    protocol: 'postgres',
    logging: false,
    dialectOptions: {
      ssl: process.env.PGSSL === '0' ? false : { require: true, rejectUnauthorized: false },
    },
  });
} else {
  sequelize = new Sequelize({
    dialect: 'sqlite',
    storage: process.env.SQLITE_STORAGE || './var/dev.sqlite',
    logging: false,
  });
}

export default sequelize;
EOF

    # Models and associations
    cat > models/index.ts << 'EOF'
import { DataTypes, InferAttributes, InferCreationAttributes, Model, CreationOptional } from 'sequelize';
import sequelize from '../db/sequelize';

export class User extends Model<InferAttributes<User>, InferCreationAttributes<User>> {
  declare id: CreationOptional<string>;
  declare email: string;
  declare passwordHash: string;
  declare firstName: CreationOptional<string | null>;
  declare lastName: CreationOptional<string | null>;
  declare isActive: CreationOptional<boolean>;
  declare lastLoginAt: CreationOptional<Date | null>;
}

export class Role extends Model<InferAttributes<Role>, InferCreationAttributes<Role>> {
  declare id: CreationOptional<string>;
  declare name: string;
}

export class Permission extends Model<InferAttributes<Permission>, InferCreationAttributes<Permission>> {
  declare id: CreationOptional<string>;
  declare name: string;
}

export class RefreshToken extends Model<InferAttributes<RefreshToken>, InferCreationAttributes<RefreshToken>> {
  declare id: CreationOptional<string>;
  declare userId: string;
  declare tokenHash: string;
  declare jti: string;
  declare revokedAt: CreationOptional<Date | null>;
  declare expiresAt: Date;
}

export class PasswordResetToken extends Model<InferAttributes<PasswordResetToken>, InferCreationAttributes<PasswordResetToken>> {
  declare id: CreationOptional<string>;
  declare userId: string;
  declare tokenHash: string;
  declare expiresAt: Date;
  declare usedAt: CreationOptional<Date | null>;
}

User.init({
  id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
  email: { type: DataTypes.STRING, allowNull: false, unique: true },
  passwordHash: { type: DataTypes.STRING, allowNull: false },
  firstName: { type: DataTypes.STRING, allowNull: true },
  lastName: { type: DataTypes.STRING, allowNull: true },
  isActive: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: true },
  lastLoginAt: { type: DataTypes.DATE, allowNull: true },
}, { sequelize, modelName: 'User', tableName: 'Users', timestamps: true });

Role.init({
  id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
  name: { type: DataTypes.STRING, allowNull: false, unique: true },
}, { sequelize, modelName: 'Role', tableName: 'Roles', timestamps: true });

Permission.init({
  id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
  name: { type: DataTypes.STRING, allowNull: false, unique: true },
}, { sequelize, modelName: 'Permission', tableName: 'Permissions', timestamps: true });

RefreshToken.init({
  id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
  userId: { type: DataTypes.UUID, allowNull: false },
  tokenHash: { type: DataTypes.STRING, allowNull: false },
  jti: { type: DataTypes.STRING, allowNull: false, unique: true },
  revokedAt: { type: DataTypes.DATE, allowNull: true },
  expiresAt: { type: DataTypes.DATE, allowNull: false },
}, { sequelize, modelName: 'RefreshToken', tableName: 'RefreshTokens', timestamps: true });

PasswordResetToken.init({
  id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
  userId: { type: DataTypes.UUID, allowNull: false },
  tokenHash: { type: DataTypes.STRING, allowNull: false },
  expiresAt: { type: DataTypes.DATE, allowNull: false },
  usedAt: { type: DataTypes.DATE, allowNull: true },
}, { sequelize, modelName: 'PasswordResetToken', tableName: 'PasswordResetTokens', timestamps: true });

// Associations
User.belongsToMany(Role, { through: 'UserRoles', foreignKey: 'userId' });
Role.belongsToMany(User, { through: 'UserRoles', foreignKey: 'roleId' });

Role.belongsToMany(Permission, { through: 'RolePermissions', foreignKey: 'roleId' });
Permission.belongsToMany(Role, { through: 'RolePermissions', foreignKey: 'permissionId' });

User.hasMany(RefreshToken, { foreignKey: 'userId' });
RefreshToken.belongsTo(User, { foreignKey: 'userId' });
User.hasMany(PasswordResetToken, { foreignKey: 'userId' });
PasswordResetToken.belongsTo(User, { foreignKey: 'userId' });

export default { sequelize, User, Role, Permission, RefreshToken, PasswordResetToken };
EOF

    echo -e "${YELLOW}Auth/RBAC: Adding Passport strategies and JWT helpers...${NC}"

    # JWT helpers
    cat > auth/jwt.ts << 'EOF'
import jwt, { SignOptions, Secret } from 'jsonwebtoken';
import crypto from 'crypto';
import { addMs } from './ttl';
import models from '../models';

export function issueAccessToken(user: any, roles: string[], permissions: string[] = []) {
  const secret: Secret = (process.env.JWT_SECRET as string) || 'change-me';
  const ttl = (process.env.JWT_ACCESS_TTL as string) || '15m';
  const payload = { sub: user.id, roles, permissions };
  const options: SignOptions = { expiresIn: ttl as any };
  return jwt.sign(payload, secret, options);
}

export async function issueRefreshToken(user: any) {
  const randomToken = crypto.randomBytes(48).toString('hex');
  const jti = crypto.randomUUID();
  const tokenHash = crypto.createHash('sha256').update(randomToken).digest('hex');
  const ttl = (process.env.JWT_REFRESH_TTL as string) || '7d';
  const expiresAt = new Date(Date.now() + addMs(ttl));
  await models.RefreshToken.create({ userId: user.id, tokenHash, jti, expiresAt });
  return { refreshToken: randomToken, jti, expiresAt };
}

export async function rotateRefreshToken(userId: string, presentedToken: string) {
  const tokenHash = crypto.createHash('sha256').update(presentedToken).digest('hex');
  const record: any = await models.RefreshToken.findOne({ where: { userId, tokenHash, revokedAt: null } });
  if (!record) return null;
  if (record.expiresAt.getTime() < Date.now()) return null;
  record.revokedAt = new Date();
  await record.save();
  return issueRefreshToken({ id: userId });
}

export function verifyAccessToken(token: string) {
  const secret: Secret = (process.env.JWT_SECRET as string) || 'change-me';
  return jwt.verify(token, secret);
}
EOF

    # TTL helper
    cat > auth/ttl.ts << 'EOF'
// Very small TTL parser supporting m,h,d suffixes
export function addMs(ttl: string): number {
  const m = ttl.match(/^(\d+)(ms|s|m|h|d)$/);
  if (!m) return 0;
  const n = parseInt(m[1], 10);
  const u = m[2];
  switch (u) {
    case 'ms': return n;
    case 's': return n * 1000;
    case 'm': return n * 60 * 1000;
    case 'h': return n * 60 * 60 * 1000;
    case 'd': return n * 24 * 60 * 60 * 1000;
    default: return 0;
  }
}
EOF

    # Passport strategies
    cat > auth/passport.ts << 'EOF'
import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import { Strategy as JwtStrategy, ExtractJwt } from 'passport-jwt';
import bcrypt from 'bcrypt';
import models, { Permission, Role, User } from '../models';

passport.serializeUser((user: any, done: (err: any, id?: any) => void) => done(null, user.id));
passport.deserializeUser(async (id: string, done: (err: any, user?: any) => void) => {
  try {
    const user = await models.User.findByPk(id);
    done(null, user);
  } catch (e) {
    done(e, undefined);
  }
});

passport.use(new LocalStrategy({ usernameField: 'email' }, async (email: string, password: string, done: (err: any, user?: any, info?: any) => void) => {
  try {
    const user: any = await models.User.findOne({ where: { email } });
    if (!user || !user.isActive) return done(null, false);
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return done(null, false);
    user.lastLoginAt = new Date();
    await user.save();
    return done(null, user);
  } catch (e) {
    return done(e);
  }
}));

passport.use(new JwtStrategy({
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: (process.env.JWT_SECRET as string) || 'change-me',
}, async (payload: any, done: (err: any, user?: any, info?: any) => void) => {
  try {
    const user: any = await models.User.findByPk(payload.sub);
    if (!user || !user.isActive) return done(null, false);
    return done(null, { id: user.id, roles: payload.roles });
  } catch (e) {
    done(e, false);
  }
}));

export default passport;
EOF

    echo -e "${YELLOW}Auth/RBAC: Adding RBAC middleware...${NC}"
    cat > middleware/rbac.ts << 'EOF'
import { Request, Response, NextFunction } from 'express';
import models from '../models';

async function getUserRoles(req: Request): Promise<string[]> {
  const u: any = (req as any).user;
  if (!u) return [];
  if (Array.isArray(u.roles) && u.roles.length) return u.roles as string[];
  if (typeof u.getRoles === 'function') {
    const rs = await u.getRoles();
    return rs.map((r: any) => r.name);
  }
  return [];
}

async function getUserPermissions(req: Request): Promise<string[]> {
  const u: any = (req as any).user;
  if (!u) return [];
  if (Array.isArray(u.permissions) && u.permissions.length) return u.permissions as string[];
  // Session user (Sequelize instance): compute via roles → permissions
  if (typeof u.getRoles === 'function') {
    const roles = await u.getRoles();
    const permsNested = await Promise.all(roles.map((r: any) => r.getPermissions()));
    const perms = Array.from(new Set(permsNested.flat().map((p: any) => p.name)));
    return perms;
  }
  return [];
}

export function requireRole(required: string[]) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const roles = await getUserRoles(req);
    if (!required.some(r => roles.includes(r))) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    next();
  };
}

export function requirePermission(required: string[]) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const perms = await getUserPermissions(req);
    if (!required.some(p => perms.includes(p))) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    next();
  };
}
EOF

    echo -e "${YELLOW}Auth/RBAC: Adding auth routes (session + JWT)...${NC}"
    cat > routes/auth.web.ts << 'EOF'
import express from 'express';
import passport from '../auth/passport';
import models from '../models';

const router = express.Router();

router.post('/login', passport.authenticate('local'), (req, res) => {
  const user = (req as any).user;
  res.json({ id: user.id, email: user.email });
});

router.post('/logout', (req, res, next) => {
  (req as any).logout((err: any) => {
    if (err) return next(err);
    res.json({ ok: true });
  });
});

router.get('/me', async (req, res) => {
  if (!(req as any).isAuthenticated || !(req as any).isAuthenticated()) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const user: any = (req as any).user;
  const roles = await user.getRoles().then((rs: any[]) => rs.map(r => r.name));
  res.json({ id: user.id, email: user.email, roles });
});

export default router;
EOF

    cat > routes/auth.api.ts << 'EOF'
import express from 'express';
import passport from '../auth/passport';
import { issueAccessToken, issueRefreshToken, rotateRefreshToken } from '../auth/jwt';
import models from '../models';
import { z } from 'zod';
import { validate } from '../middleware/validate';
import { sendPasswordReset } from '../services/email';
import crypto from 'crypto';
import { addMs } from '../auth/ttl';

const router = express.Router();

router.post('/login', (req, res, next) => {
  passport.authenticate('local', { session: false }, async (err: any, user: any, info: any) => {
    if (err || !user) return res.status(401).json({ error: 'Invalid credentials' });
    const roles = await user.getRoles().then((rs: any[]) => rs.map((r: any) => r.name));
    // collect permissions from roles
    const roleInstances = await user.getRoles();
    const permsNested = await Promise.all(roleInstances.map((r: any) => r.getPermissions()));
    const permissions = Array.from(new Set(permsNested.flat().map((p: any) => p.name)));
    const accessToken = issueAccessToken(user, roles, permissions);
    const { refreshToken, jti, expiresAt } = await issueRefreshToken(user);
    res.json({ accessToken, refreshToken, jti, expiresAt });
  })(req, res, next);
});

router.post('/refresh', async (req, res) => {
  const { userId, refreshToken } = req.body || {};
  if (!userId || !refreshToken) return res.status(400).json({ error: 'Missing params' });
  const rotated = await rotateRefreshToken(userId, refreshToken);
  if (!rotated) return res.status(401).json({ error: 'Invalid refresh token' });
  const user = await models.User.findByPk(userId);
  if (!user) return res.status(401).json({ error: 'Invalid user' });
  const roles = await (user as any).getRoles().then((rs: any[]) => rs.map(r => r.name));
  const accessToken = issueAccessToken(user, roles);
  res.json({ accessToken, refreshToken: rotated.refreshToken, jti: rotated.jti, expiresAt: rotated.expiresAt });
});

router.get('/me', passport.authenticate('jwt', { session: false }), async (req, res) => {
  res.json({ user: (req as any).user });
});

// Password reset: request
const requestResetSchema = z.object({ email: z.string().email() });
router.post('/request-reset', validate(requestResetSchema), async (req, res) => {
  const { email } = req.body as { email: string };
  const user = await models.User.findOne({ where: { email } });
  if (!user) return res.status(200).json({ ok: true }); // do not reveal
  const rawToken = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
  const expiresAt = new Date(Date.now() + addMs('1h'));
  await models.PasswordResetToken.create({ userId: (user as any).id, tokenHash, expiresAt });
  await sendPasswordReset(email, rawToken, (user as any).id);
  return res.json({ ok: true });
});

// Password reset: consume
const resetSchema = z.object({ userId: z.string().uuid(), token: z.string(), password: z.string().min(8) });
router.post('/reset', validate(resetSchema), async (req, res) => {
  const { userId, token, password } = req.body as { userId: string; token: string; password: string };
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const rec: any = await models.PasswordResetToken.findOne({ where: { userId, tokenHash, usedAt: null } });
  if (!rec || rec.expiresAt.getTime() < Date.now()) return res.status(400).json({ error: 'Invalid or expired token' });
  const user: any = await models.User.findByPk(userId);
  if (!user) return res.status(400).json({ error: 'Invalid user' });
  const bcrypt = require('bcrypt');
  user.passwordHash = await bcrypt.hash(password, 12);
  await user.save();
  rec.usedAt = new Date();
  await rec.save();
  return res.json({ ok: true });
});

export default router;
EOF

    echo -e "${YELLOW}Auth/RBAC: Creating initial migration and seeders...${NC}"
    cat > db/migrations/20231010120000-init-auth.js << 'EOF'
'use strict';

module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('Users', {
      id: { type: Sequelize.UUID, primaryKey: true, allowNull: false },
      email: { type: Sequelize.STRING, allowNull: false, unique: true },
      passwordHash: { type: Sequelize.STRING, allowNull: false },
      firstName: { type: Sequelize.STRING },
      lastName: { type: Sequelize.STRING },
      isActive: { type: Sequelize.BOOLEAN, allowNull: false, defaultValue: true },
      lastLoginAt: { type: Sequelize.DATE },
      createdAt: { type: Sequelize.DATE, allowNull: false, defaultValue: Sequelize.literal('CURRENT_TIMESTAMP') },
      updatedAt: { type: Sequelize.DATE, allowNull: false, defaultValue: Sequelize.literal('CURRENT_TIMESTAMP') },
    });

    await queryInterface.createTable('Roles', {
      id: { type: Sequelize.UUID, primaryKey: true, allowNull: false },
      name: { type: Sequelize.STRING, allowNull: false, unique: true },
      createdAt: { type: Sequelize.DATE, allowNull: false, defaultValue: Sequelize.literal('CURRENT_TIMESTAMP') },
      updatedAt: { type: Sequelize.DATE, allowNull: false, defaultValue: Sequelize.literal('CURRENT_TIMESTAMP') },
    });

    await queryInterface.createTable('Permissions', {
      id: { type: Sequelize.UUID, primaryKey: true, allowNull: false },
      name: { type: Sequelize.STRING, allowNull: false, unique: true },
      createdAt: { type: Sequelize.DATE, allowNull: false, defaultValue: Sequelize.literal('CURRENT_TIMESTAMP') },
      updatedAt: { type: Sequelize.DATE, allowNull: false, defaultValue: Sequelize.literal('CURRENT_TIMESTAMP') },
    });

    await queryInterface.createTable('UserRoles', {
      userId: { type: Sequelize.UUID, allowNull: false },
      roleId: { type: Sequelize.UUID, allowNull: false },
      createdAt: { type: Sequelize.DATE, allowNull: false, defaultValue: Sequelize.literal('CURRENT_TIMESTAMP') },
      updatedAt: { type: Sequelize.DATE, allowNull: false, defaultValue: Sequelize.literal('CURRENT_TIMESTAMP') },
    });
    await queryInterface.addConstraint('UserRoles', { fields: ['userId', 'roleId'], type: 'unique', name: 'ux_user_roles_user_role' });

    await queryInterface.createTable('RolePermissions', {
      roleId: { type: Sequelize.UUID, allowNull: false },
      permissionId: { type: Sequelize.UUID, allowNull: false },
      createdAt: { type: Sequelize.DATE, allowNull: false, defaultValue: Sequelize.literal('CURRENT_TIMESTAMP') },
      updatedAt: { type: Sequelize.DATE, allowNull: false, defaultValue: Sequelize.literal('CURRENT_TIMESTAMP') },
    });
    await queryInterface.addConstraint('RolePermissions', { fields: ['roleId', 'permissionId'], type: 'unique', name: 'ux_role_permissions_role_perm' });

    await queryInterface.createTable('RefreshTokens', {
      id: { type: Sequelize.UUID, primaryKey: true, allowNull: false },
      userId: { type: Sequelize.UUID, allowNull: false },
      tokenHash: { type: Sequelize.STRING, allowNull: false },
      jti: { type: Sequelize.STRING, allowNull: false, unique: true },
      revokedAt: { type: Sequelize.DATE },
      expiresAt: { type: Sequelize.DATE, allowNull: false },
      createdAt: { type: Sequelize.DATE, allowNull: false, defaultValue: Sequelize.literal('CURRENT_TIMESTAMP') },
      updatedAt: { type: Sequelize.DATE, allowNull: false, defaultValue: Sequelize.literal('CURRENT_TIMESTAMP') },
    });

    await queryInterface.createTable('PasswordResetTokens', {
      id: { type: Sequelize.UUID, primaryKey: true, allowNull: false },
      userId: { type: Sequelize.UUID, allowNull: false },
      tokenHash: { type: Sequelize.STRING, allowNull: false },
      expiresAt: { type: Sequelize.DATE, allowNull: false },
      usedAt: { type: Sequelize.DATE },
      createdAt: { type: Sequelize.DATE, allowNull: false, defaultValue: Sequelize.literal('CURRENT_TIMESTAMP') },
      updatedAt: { type: Sequelize.DATE, allowNull: false, defaultValue: Sequelize.literal('CURRENT_TIMESTAMP') },
    });
  },

  async down(queryInterface) {
    await queryInterface.dropTable('RefreshTokens');
    await queryInterface.dropTable('RolePermissions');
    await queryInterface.dropTable('UserRoles');
    await queryInterface.dropTable('Permissions');
    await queryInterface.dropTable('Roles');
    await queryInterface.dropTable('Users');
    await queryInterface.dropTable('PasswordResetTokens');
  }
};
EOF

    cat > db/seeders/20231010121000-seed-rbac.js << 'EOF'
'use strict';

const bcrypt = require('bcrypt');
const { randomUUID } = require('crypto');

module.exports = {
  async up(queryInterface, Sequelize) {
    const [adminRoleId, userRoleId] = [randomUUID(), randomUUID()];
    const [usersReadId, usersWriteId, rolesReadId, rolesWriteId] = [
      randomUUID(),
      randomUUID(),
      randomUUID(),
      randomUUID(),
    ];

    await queryInterface.bulkInsert('Roles', [
      { id: adminRoleId, name: 'admin', createdAt: new Date(), updatedAt: new Date() },
      { id: userRoleId, name: 'user', createdAt: new Date(), updatedAt: new Date() },
    ]);

    await queryInterface.bulkInsert('Permissions', [
      { id: usersReadId, name: 'users.read', createdAt: new Date(), updatedAt: new Date() },
      { id: usersWriteId, name: 'users.write', createdAt: new Date(), updatedAt: new Date() },
      { id: rolesReadId, name: 'roles.read', createdAt: new Date(), updatedAt: new Date() },
      { id: rolesWriteId, name: 'roles.write', createdAt: new Date(), updatedAt: new Date() },
    ]);

    await queryInterface.bulkInsert('RolePermissions', [
      { roleId: adminRoleId, permissionId: usersReadId, createdAt: new Date(), updatedAt: new Date() },
      { roleId: adminRoleId, permissionId: usersWriteId, createdAt: new Date(), updatedAt: new Date() },
      { roleId: adminRoleId, permissionId: rolesReadId, createdAt: new Date(), updatedAt: new Date() },
      { roleId: adminRoleId, permissionId: rolesWriteId, createdAt: new Date(), updatedAt: new Date() },
    ]);

    const adminEmail = process.env.ADMIN_EMAIL || 'admin@example.com';
    const adminPassword = process.env.ADMIN_PASSWORD || 'Admin123!';
    const passwordHash = await bcrypt.hash(adminPassword, 12);
    const adminUserId = randomUUID();

    await queryInterface.bulkInsert('Users', [
      { id: adminUserId, email: adminEmail, passwordHash, isActive: true, createdAt: new Date(), updatedAt: new Date() },
    ]);

    await queryInterface.bulkInsert('UserRoles', [
      { userId: adminUserId, roleId: adminRoleId, createdAt: new Date(), updatedAt: new Date() },
    ]);
  },

  async down(queryInterface) {
    await queryInterface.bulkDelete('UserRoles', null, {});
    await queryInterface.bulkDelete('Users', null, {});
    await queryInterface.bulkDelete('RolePermissions', null, {});
    await queryInterface.bulkDelete('Permissions', null, {});
    await queryInterface.bulkDelete('Roles', null, {});
  }
};
EOF

    echo -e "${YELLOW}Auth/RBAC: Running migrations/seeds (dev by default)...${NC}"
    if [ -z "${RUN_DB_MIGRATIONS+x}" ]; then RUN_DB_MIGRATIONS=1; fi
    if [ -z "${RUN_DB_SEEDS+x}" ]; then RUN_DB_SEEDS=1; fi
    if [ "${NODE_ENV}" = "production" ]; then
      # Default skip in prod unless explicitly enabled
      if [ "${RUN_DB_MIGRATIONS}" = "1" ]; then echo -e "${YELLOW}Skipping migrations in production by default.${NC}"; RUN_DB_MIGRATIONS=0; fi
      if [ "${RUN_DB_SEEDS}" = "1" ]; then echo -e "${YELLOW}Skipping seeds in production by default.${NC}"; RUN_DB_SEEDS=0; fi
    fi
    if [ "${RUN_DB_MIGRATIONS}" = "1" ]; then npx sequelize-cli db:migrate; fi
    if [ "${RUN_DB_SEEDS}" = "1" ]; then npx sequelize-cli db:seed:all; fi

    echo -e "${YELLOW}Auth/RBAC: Updating server to wire sessions, Passport, and routes...${NC}"
    cat > app.ts << 'EOF'
import createError from 'http-errors';
import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import cookieParser from 'cookie-parser';
import logger from 'morgan';
import session from 'express-session';
import cors from 'cors';
import passport from './auth/passport';
import sequelize from './db/sequelize';
import indexRouter from './routes/index';
import authWeb from './routes/auth.web';
import authApi from './routes/auth.api';
import adminUsers from './routes/admin.users';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

const app = express();

// Logger (plain in dev, combined in prod)
app.use(logger(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

// Serve static files from public directory
app.use(express.static(path.join(__dirname, 'public')));

// Serve React client build files statically from dist/client
app.use(express.static(path.join(__dirname, 'dist/client')));

// Security
app.use(helmet());
const windowMs = parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10);
const maxReq = parseInt(process.env.RATE_LIMIT_MAX || '100', 10);
app.use(['/auth', '/api/auth'], rateLimit({ windowMs, max: maxReq }));

// Sessions (web) with Sequelize store
const SequelizeStore = require('connect-session-sequelize')(session.Store);
const store = new SequelizeStore({ db: sequelize });
const isProduction = process.env.NODE_ENV === 'production';
if (isProduction) {
  app.set('trust proxy', 1);
}
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-me',
  resave: false,
  saveUninitialized: false,
  store,
  cookie: { httpOnly: true, sameSite: 'lax', secure: isProduction },
}));
store.sync();

// CORS from env
const origins = (process.env.CLIENT_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
app.use(cors(origins.length ? { origin: origins, credentials: true } : undefined));
app.use(passport.initialize());
app.use(passport.session());

// API routes
app.use('/api', indexRouter);
app.use('/auth', authWeb); // session-based web auth
app.use('/api/auth', authApi); // JWT-based API auth
app.use('/api/admin/users', adminUsers);

// Catch-all handler to serve React app for client-side routing
app.get('*', (req: Request, res: Response) => {
  res.sendFile(path.join(__dirname, 'dist/client', 'index.html'));
});

// 404 handler
app.use(function(req: Request, res: Response, next: NextFunction) {
  next(createError(404));
});

// error handler
app.use(function(err: any, req: Request, res: Response, next: NextFunction) {
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};
  res.status(err.status || 500);
  res.json({ error: err.message });
});

export default app;
EOF

    echo -e "${YELLOW}Auth/RBAC: Adding validation and email service...${NC}"
    cat > middleware/validate.ts << 'EOF'
import type { ZodSchema, ZodError } from 'zod';
import { Request, Response, NextFunction } from 'express';

// Validates req.body by default. For schemas expecting a different shape,
// create a wrapper schema or adjust below as needed.
export function validate(schema: ZodSchema<any>) {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      schema.parse(req.body);
      next();
    } catch (e) {
      const err = e as ZodError;
      if (err?.issues) {
        return res.status(400).json({ error: 'ValidationError', details: err.issues });
      }
      next(e);
    }
  };
}
EOF

    echo -e "${YELLOW}Admin: Adding Users CRUD endpoints...${NC}"
    cat > routes/admin.users.ts << 'EOF'
import express from 'express';
import { z } from 'zod';
import { validate } from '../middleware/validate';
import models from '../models';
import { requirePermission } from '../middleware/rbac';
import { sendPasswordReset } from '../services/email';

const router = express.Router();

// List users with optional search and pagination
router.get('/', requirePermission(['users.read']), async (req, res) => {
  const q = (req.query.q as string) || '';
  const page = parseInt((req.query.page as string) || '1', 10);
  const pageSize = parseInt((req.query.pageSize as string) || '10', 10);
  const offset = (page - 1) * pageSize;
  const where: any = q
    ? { email: { [require('sequelize').Op.like]: `%${q}%` } }
    : {};
  const { rows, count } = await (models as any).User.findAndCountAll({ where, limit: pageSize, offset, order: [['createdAt', 'DESC']] });
  res.json({ items: rows, total: count, page, pageSize });
});

const createSchema = z.object({
  email: z.string().email(),
  firstName: z.string().optional(),
  lastName: z.string().optional(),
  password: z.string().min(8),
  roles: z.array(z.string()).default(['user'])
});

router.post('/', requirePermission(['users.write']), validate(createSchema), async (req, res) => {
  const { email, firstName, lastName, password, roles } = req.body;
  const existing = await (models as any).User.findOne({ where: { email } });
  if (existing) return res.status(409).json({ error: 'Email already exists' });
  const bcrypt = require('bcrypt');
  const user = await (models as any).User.create({ email, firstName, lastName, passwordHash: await bcrypt.hash(password, 12) });
  if (roles?.length) {
    const roleModels = await (models as any).Role.findAll({ where: { name: roles } });
    await (user as any).setRoles(roleModels);
  }
  res.status(201).json(user);
});

const updateSchema = z.object({
  email: z.string().email().optional(),
  firstName: z.string().optional(),
  lastName: z.string().optional(),
  password: z.string().min(8).optional(),
  roles: z.array(z.string()).optional()
});

router.put('/:id', requirePermission(['users.write']), validate(updateSchema), async (req, res) => {
  const { id } = req.params as any;
  const { email, firstName, lastName, password, roles } = req.body;
  const user: any = await (models as any).User.findByPk(id);
  if (!user) return res.status(404).json({ error: 'Not found' });
  if (email) user.email = email;
  if (firstName !== undefined) user.firstName = firstName;
  if (lastName !== undefined) user.lastName = lastName;
  if (password) {
    const bcrypt = require('bcrypt');
    user.passwordHash = await bcrypt.hash(password, 12);
  }
  await user.save();
  if (roles) {
    const roleModels = await (models as any).Role.findAll({ where: { name: roles } });
    await user.setRoles(roleModels);
  }
  res.json(user);
});

const statusSchema = z.object({ isActive: z.boolean() });
router.patch('/:id/status', requirePermission(['users.write']), validate(statusSchema), async (req, res) => {
  const { id } = req.params as any;
  const { isActive } = req.body as any;
  const user: any = await (models as any).User.findByPk(id);
  if (!user) return res.status(404).json({ error: 'Not found' });
  user.isActive = isActive;
  await user.save();
  res.json(user);
});

router.delete('/:id', requirePermission(['users.write']), async (req, res) => {
  const { id } = req.params as any;
  const user: any = await (models as any).User.findByPk(id);
  if (!user) return res.status(404).json({ error: 'Not found' });
  await user.destroy();
  res.json({ ok: true });
});

router.post('/:id/reset', requirePermission(['users.write']), async (req, res) => {
  const { id } = req.params as any;
  const user: any = await (models as any).User.findByPk(id);
  if (!user) return res.status(404).json({ error: 'Not found' });
  const crypto = require('crypto');
  const { addMs } = require('../auth/ttl');
  const rawToken = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
  const expiresAt = new Date(Date.now() + addMs('1h'));
  await (models as any).PasswordResetToken.create({ userId: user.id, tokenHash, expiresAt });
  await sendPasswordReset(user.email, rawToken, user.id);
  res.json({ ok: true });
});

export default router;
EOF

    mkdir -p services
    cat > services/email.ts << 'EOF'
import nodemailer from 'nodemailer';

export async function sendPasswordReset(to: string, token: string, userId: string) {
  const host = process.env.SMTP_HOST;
  const port = parseInt(process.env.SMTP_PORT || '587', 10);
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  const from = process.env.SMTP_FROM || 'no-reply@example.com';

  const base = process.env.PUBLIC_BASE_URL || `http://localhost:${process.env.PORT || '3333'}`;
  const resetUrl = `${base}/reset?token=${token}&uid=${userId}`;

  if (!host || !user || !pass) {
    console.log(`[email] SMTP not configured. Share this reset link: ${resetUrl}`);
    return;
  }

  const transport = nodemailer.createTransport({ host, port, secure: port === 465, auth: { user, pass } });
  await transport.sendMail({
    from,
    to,
    subject: 'Password reset',
    html: `<p>Click to reset your password:</p><p><a href="${resetUrl}">${resetUrl}</a></p>`,
  });
}
EOF

    echo -e "${GREEN}✅ Auth/RBAC scaffolding complete (models, strategies, routes, server wiring).${NC}"
fi

# Step 10: Create React client using the existing script logic
echo -e "${YELLOW}Step 10: Setting up React client with shadcn/ui...${NC}"

# Initialize create-react-app with TypeScript
npx create-react-app client --template typescript

# Remove git repository from client (we'll track the whole project as one repo)
rm -rf client/.git

# Navigate into the client directory
cd client

# Step 10.1: Update React app name and branding
echo -e "${YELLOW}Step 10.1: Updating React app name and branding...${NC}"

# Update package.json name
npm pkg set name="${PROJECT_NAME}-client"

# Update public/index.html title and meta
sed -i '' "s/<title>React App<\/title>/<title>${PROJECT_NAME}<\/title>/" public/index.html
sed -i '' "s/content=\"Web site created using create-react-app\"/content=\"${PROJECT_NAME} - Full-stack TypeScript application\"/" public/index.html

# Update manifest.json
sed -i '' "s/\"name\": \"React App\"/\"name\": \"${PROJECT_NAME}\"/" public/manifest.json
sed -i '' "s/\"short_name\": \"React App\"/\"short_name\": \"${PROJECT_NAME}\"/" public/manifest.json

# Step 10.2: Download and replace icon files
echo -e "${YELLOW}Step 10.2: Downloading and replacing icon files...${NC}"

# Download the dice.ico file
curl -L "https://raw.githubusercontent.com/Pradeeps-repo/appstarter/refs/heads/main/dice.ico" -o public/favicon.ico

# Create PNG versions for different sizes using the downloaded icon
# Note: We'll use the .ico file directly for favicon and create simple placeholder PNGs
# Copy the ico file as png placeholders (browsers will handle ico format fine)
cp public/favicon.ico public/logo192.png
cp public/favicon.ico public/logo512.png

echo -e "${GREEN}✅ React app branding updated with project name: ${PROJECT_NAME}${NC}"
echo -e "${GREEN}✅ Icon files replaced with dice.ico${NC}"

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

# Install client routing and add shadcn inputs
npm install --save react-router-dom
npx shadcn@latest add input
npx shadcn@latest add label
npx shadcn@latest add dialog
npx shadcn@latest add https://www.shadcnui-blocks.com/r/table-10.json || true

# Local header component
mkdir -p src/components
cat > src/components/AppHeader.tsx << EOF
import { useEffect, useState } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { Button } from './ui/button';
import { CircleUser } from 'lucide-react';

export default function AppHeader() {
  const [email, setEmail] = useState<string | null>(null);
  const [isAdmin, setIsAdmin] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    (async () => {
      try {
        const res = await fetch('/auth/me');
        if (!res.ok) return;
        const data = await res.json();
        setEmail(data.email || null);
        const roles: string[] = data.roles || [];
        setIsAdmin(roles.includes('admin'));
      } catch {}
    })();
  }, [location.pathname]);

  async function onLogout() {
    try {
      await fetch('/auth/logout', { method: 'POST' });
    } finally {
      navigate('/');
    }
  }

  return (
    <header className="sticky top-0 z-40 w-full border-b bg-background">
      <div className="container mx-auto h-14 flex items-center justify-between px-4">
        <Link to="/home" className="font-semibold">${PROJECT_NAME}</Link>
        <nav className="flex items-center gap-4">
          <Button asChild variant="ghost" size="sm"><Link to="/home">Home</Link></Button>
          {isAdmin && (
            <Button asChild variant="ghost" size="sm"><Link to="/admin/users">Users</Link></Button>
          )}
        </nav>
        <div className="flex items-center gap-3">
          {email ? (
            <>
              <CircleUser className="w-5 h-5" />
              <span className="text-sm text-muted-foreground hidden sm:inline">{email}</span>
              <Button size="sm" variant="outline" onClick={onLogout}>Logout</Button>
            </>
          ) : (
            <Button asChild size="sm"><Link to="/">Login</Link></Button>
          )}
        </div>
      </div>
    </header>
  );
}
EOF

if [ ! -f src/components/customized/table/table-10.tsx ]; then
mkdir -p src/components/customized/table
cat > src/components/customized/table/table-10.tsx << 'EOF'
import React from 'react';

type Props = {
  data: any[];
  columns: { header: string; accessorKey?: string; cell?: (ctx: any) => React.ReactNode }[];
  total: number;
  page: number;
  pageSize: number;
  onPageChange: (p: number) => void;
  onPageSizeChange: (s: number) => void;
};

export default function Table10({ data, columns, total, page, pageSize, onPageChange, onPageSizeChange }: Props) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  return (
    <div className="w-full">
      <div className="overflow-x-auto border rounded-md">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-muted/50">
              {columns.map((c, i) => (<th key={i} className="text-left p-2 font-semibold">{c.header}</th>))}
            </tr>
          </thead>
          <tbody>
            {data.map((row, ri) => (
              <tr key={ri} className="border-t">
                {columns.map((c, ci) => (
                  <td key={ci} className="p-2">{c.cell ? c.cell({ row: { original: row } }) : (row as any)[c.accessorKey || '']}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="flex items-center justify-between mt-3">
        <div>Page {page} of {totalPages} • {total} total</div>
        <div className="flex items-center gap-2">
          <button disabled={page<=1} onClick={() => onPageChange(page-1)} className="px-2 py-1 border rounded">Prev</button>
          <button disabled={page>=totalPages} onClick={() => onPageChange(page+1)} className="px-2 py-1 border rounded">Next</button>
          <select value={pageSize} onChange={e => onPageSizeChange(parseInt(e.target.value,10))} className="border rounded p-1">
            {[10,20,50].map(s => <option key={s} value={s}>{s}/page</option>)}
          </select>
        </div>
      </div>
    </div>
  );
}
EOF
fi

# Delete App.css and update App.tsx
rm -f src/App.css

cat > src/App.tsx << EOF
import { Routes, Route, Link } from 'react-router-dom';
import { Button } from './components/ui/button';
import AppHeader from './components/AppHeader';
import Login from './pages/Login';
import AdminUsers from './pages/AdminUsers';
import ProtectedRoute from './components/ProtectedRoute';
import ForgotPassword from './pages/ForgotPassword';
import ResetPassword from './pages/ResetPassword';

function Home() {
  return (
    <div className="min-h-screen">
      <AppHeader />
      <main className="flex flex-col items-center justify-center p-6">
        <img src="/favicon.ico" className="w-24 h-24 mb-6" alt="${PROJECT_NAME} logo" />
        <h1 className="text-4xl font-bold mb-4">${PROJECT_NAME}</h1>
        <p className="text-muted-foreground mb-6">Full-stack Express TypeScript + React + shadcn/ui</p>
        <Button asChild>
          <a href="https://reactjs.org" target="_blank" rel="noopener noreferrer">Learn React</a>
        </Button>
      </main>
    </div>
  );
}

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Login />} />
      <Route path="/home" element={<Home />} />
      <Route path="/forgot" element={<ForgotPassword />} />
      <Route path="/reset" element={<ResetPassword />} />
      <Route path="/admin/users" element={<ProtectedRoute roles={["admin"]}><AdminUsers /></ProtectedRoute>} />
    </Routes>
  );
}
EOF

# Wrap with BrowserRouter
cat > src/index.tsx << 'EOF'
import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import './index.css';
import App from './App';

const root = ReactDOM.createRoot(document.getElementById('root') as HTMLElement);
root.render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>
);
EOF

# Create Login page using shadcn components
mkdir -p src/pages
cat > src/pages/Login.tsx << 'EOF'
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Label } from '../components/ui/label';

export default function Login() {
  const [email, setEmail] = useState('admin@example.com');
  const [password, setPassword] = useState('Admin123!');
  const [message, setMessage] = useState<string | null>(null);
  const navigate = useNavigate();

  async function loginSession(e: React.FormEvent) {
    e.preventDefault();
    setMessage(null);
    try {
      const res = await fetch('/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });
      if (!res.ok) throw new Error('Invalid credentials');
      await res.json();
      navigate('/home');
    } catch (err: any) {
      setMessage(err.message || 'Login failed');
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-6">
      <div className="w-full max-w-sm border rounded-lg p-6">
        <h1 className="text-2xl font-semibold mb-4">Sign in</h1>
        <form className="space-y-4" onSubmit={loginSession}>
          <div className="grid gap-2">
            <Label htmlFor="email">Email</Label>
            <Input id="email" type="email" value={email} onChange={e => setEmail(e.target.value)} required />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="password">Password</Label>
            <Input id="password" type="password" value={password} onChange={e => setPassword(e.target.value)} required />
          </div>
          <Button type="submit" className="w-full">Login</Button>
        </form>
        <div className="mt-3 text-right">
          <a href="/forgot" className="text-sm text-blue-600 hover:underline">Forgot password?</a>
        </div>
        {message && <p className="text-sm text-muted-foreground mt-4">{message}</p>}
      </div>
    </div>
  );
}
EOF

# Forgot Password page
cat > src/pages/ForgotPassword.tsx << 'EOF'
import { useState } from 'react';
import AppHeader from '../components/AppHeader';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Label } from '../components/ui/label';

export default function ForgotPassword() {
  const [email, setEmail] = useState('');
  const [msg, setMsg] = useState<string | null>(null);
  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setMsg(null);
    const res = await fetch('/api/auth/request-reset', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email }) });
    setMsg(res.ok ? 'If the email exists, a reset link was sent or logged.' : 'Request failed');
  }
  return (
    <div className="min-h-screen">
      <AppHeader />
      <main className="max-w-md mx-auto p-6">
        <h1 className="text-2xl font-semibold mb-4">Forgot password</h1>
        <form className="space-y-4" onSubmit={submit}>
          <div>
            <Label htmlFor="email">Email</Label>
            <Input id="email" value={email} onChange={e => setEmail(e.target.value)} required />
          </div>
          <Button type="submit" className="w-full">Send reset link</Button>
        </form>
        {msg && <p className="text-sm text-muted-foreground mt-4">{msg}</p>}
      </main>
    </div>
  );
}
EOF

# Reset Password page
cat > src/pages/ResetPassword.tsx << 'EOF'
import { useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import AppHeader from '../components/AppHeader';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Label } from '../components/ui/label';

export default function ResetPassword() {
  const [params] = useSearchParams();
  const [password, setPassword] = useState('');
  const [msg, setMsg] = useState<string | null>(null);
  const navigate = useNavigate();
  const token = params.get('token') || '';
  const userId = params.get('uid') || '';

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setMsg(null);
    const res = await fetch('/api/auth/reset', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token, userId, password }) });
    if (res.ok) {
      setMsg('Password updated. Redirecting to login...');
      setTimeout(() => navigate('/'), 1200);
    } else {
      setMsg('Reset failed. Link may be invalid or expired.');
    }
  }

  return (
    <div className="min-h-screen">
      <AppHeader />
      <main className="max-w-md mx-auto p-6">
        <h1 className="text-2xl font-semibold mb-4">Reset password</h1>
        <form className="space-y-4" onSubmit={submit}>
          <div>
            <Label htmlFor="password">New password</Label>
            <Input id="password" type="password" value={password} onChange={e => setPassword(e.target.value)} required />
          </div>
          <Button type="submit" className="w-full">Update password</Button>
        </form>
        {msg && <p className="text-sm text-muted-foreground mt-4">{msg}</p>}
      </main>
    </div>
  );
}
EOF

# Admin Users page (shadcn table integration)
cat > src/pages/AdminUsers.tsx << 'EOF'
import { useEffect, useMemo, useState } from 'react';
import AppHeader from '../components/AppHeader';
import { Button } from '../components/ui/button';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '../components/ui/dialog';
import { Input } from '../components/ui/input';
import { Label } from '../components/ui/label';

type User = { id: string; email: string; firstName?: string; lastName?: string; isActive: boolean; createdAt: string };

export default function AdminUsers() {
  const [items, setItems] = useState<User[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [q, setQ] = useState('');
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({ email: '', firstName: '', lastName: '', password: '', roles: 'user' });

  async function load() {
    const res = await fetch(`/api/admin/users?q=${encodeURIComponent(q)}&page=${page}&pageSize=${pageSize}`);
    if (res.status === 403) {
      setItems([]);
      setTotal(0);
      return;
    }
    const data = await res.json();
    setItems(data.items || []);
    setTotal(data.total || 0);
  }

  useEffect(() => { load(); }, [q, page, pageSize]);

  async function createUser() {
    const body = { ...form, roles: form.roles.split(',').map(r => r.trim()).filter(Boolean) };
    const res = await fetch('/api/admin/users', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    if (res.ok) { setOpen(false); setForm({ email: '', firstName: '', lastName: '', password: '', roles: 'user' }); load(); }
  }

  async function toggleActive(user: User) {
    await fetch(`/api/admin/users/${user.id}/status`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ isActive: !user.isActive }) });
    load();
  }

  async function removeUser(user: User) {
    await fetch(`/api/admin/users/${user.id}`, { method: 'DELETE' });
    load();
  }

  async function resetPassword(user: User) {
    await fetch(`/api/admin/users/${user.id}/reset`, { method: 'POST' });
    alert('If SMTP is configured, a reset email was sent; otherwise the link was logged on server.');
  }

  return (
    <div className="min-h-screen">
      <AppHeader />
      <div className="container mx-auto py-8">
        <div className="flex items-center justify-between mb-4">
          <h1 className="text-2xl font-semibold">Users</h1>
          <Dialog open={open} onOpenChange={setOpen}>
            <DialogTrigger asChild>
              <Button>New User</Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Create User</DialogTitle>
              </DialogHeader>
              <div className="grid gap-3">
                <div>
                  <Label htmlFor="email">Email</Label>
                  <Input id="email" value={form.email} onChange={e => setForm({ ...form, email: e.target.value })} />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <Label htmlFor="firstName">First name</Label>
                    <Input id="firstName" value={form.firstName} onChange={e => setForm({ ...form, firstName: e.target.value })} />
                  </div>
                  <div>
                    <Label htmlFor="lastName">Last name</Label>
                    <Input id="lastName" value={form.lastName} onChange={e => setForm({ ...form, lastName: e.target.value })} />
                  </div>
                </div>
                <div>
                  <Label htmlFor="password">Password</Label>
                  <Input id="password" type="password" value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} />
                </div>
                <div>
                  <Label htmlFor="roles">Roles (comma separated)</Label>
                  <Input id="roles" value={form.roles} onChange={e => setForm({ ...form, roles: e.target.value })} />
                </div>
                <Button onClick={createUser}>Create</Button>
              </div>
            </DialogContent>
          </Dialog>
        </div>
        <div className="mb-4">
          <Input placeholder="Search email..." value={q} onChange={e => { setPage(1); setQ(e.target.value); }} />
        </div>
        <div className="overflow-x-auto border rounded-md">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-muted/50">
                <th className="text-left p-2 font-semibold">Email</th>
                <th className="text-left p-2 font-semibold">Name</th>
                <th className="text-left p-2 font-semibold">Active</th>
                <th className="text-left p-2 font-semibold">Created</th>
                <th className="text-left p-2 font-semibold">Actions</th>
              </tr>
            </thead>
            <tbody>
              {items.map((u) => (
                <tr key={u.id} className="border-t">
                  <td className="p-2">{u.email}</td>
                  <td className="p-2">{`${u.firstName || ''} ${u.lastName || ''}`.trim()}</td>
                  <td className="p-2">{u.isActive ? 'Yes' : 'No'}</td>
                  <td className="p-2">{new Date(u.createdAt).toLocaleString()}</td>
                  <td className="p-2">
                    <div className="flex gap-2">
                      <Button size="sm" variant="outline" onClick={() => toggleActive(u)}>{u.isActive ? 'Deactivate' : 'Activate'}</Button>
                      <Button size="sm" variant="destructive" onClick={() => removeUser(u)}>Delete</Button>
                      <Button size="sm" onClick={() => resetPassword(u)}>Reset</Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="flex items-center justify-between mt-3">
          <div>Page {page} of {Math.max(1, Math.ceil(total / pageSize))} • {total} total</div>
          <div className="flex items-center gap-2">
            <button disabled={page<=1} onClick={() => setPage(page-1)} className="px-2 py-1 border rounded">Prev</button>
            <button disabled={page>=Math.max(1, Math.ceil(total / pageSize))} onClick={() => setPage(page+1)} className="px-2 py-1 border rounded">Next</button>
            <select value={pageSize} onChange={e => setPageSize(parseInt(e.target.value,10))} className="border rounded p-1">
              {[10,20,50].map(s => <option key={s} value={s}>{s}/page</option>)}
            </select>
          </div>
        </div>
      </div>
    </div>
  );
}
EOF

# ProtectedRoute component
mkdir -p src/components
cat > src/components/ProtectedRoute.tsx << 'EOF'
import { ReactNode, useEffect, useState } from 'react';
import { Navigate } from 'react-router-dom';

type Props = { children: ReactNode; roles?: string[] };

export default function ProtectedRoute({ children, roles }: Props) {
  const [allowed, setAllowed] = useState<boolean | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const res = await fetch('/auth/me');
        if (!res.ok) return setAllowed(false);
        const data = await res.json();
        if (!roles || roles.length === 0) return setAllowed(true);
        const userRoles: string[] = data.roles || [];
        setAllowed(roles.some(r => userRoles.includes(r)));
      } catch {
        setAllowed(false);
      }
    })();
  }, [roles?.join(',')]);

  if (allowed === null) return <div className="p-4 text-center text-sm text-muted-foreground">Loading...</div>;
  return allowed ? <>{children}</> : <Navigate to="/" replace />;
}
EOF

# AdminLink no longer needed; logic moved into AppHeader

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

# Step 13: Initialize Git repository and create initial commit
echo -e "${YELLOW}Step 13: Initializing Git repository...${NC}"

# Initialize git repository
git init

# # Add all files to git (respecting .gitignore)
# git add .

# # Create initial commit
# git commit -m "Initial commit"

echo -e "${GREEN}✅ Git repository initialized with initial commit${NC}"

# Step 13.1: Add Cursor rules for shadcn/ui usage
echo -e "${YELLOW}Adding .cursorrules for shadcn/ui guidance...${NC}"
cat > .cursorrules << 'EOF'
---
description: "Use shadcn/ui components as needed for any UI code"
patterns: "*.tsx"
---

# Shadcn UI Components

This project uses @shadcn/ui for UI components. These are beautifully designed, accessible components that you can copy and paste into your apps.

## Finding and Using Components

Components are available in the `src/components/ui` directory, following the aliases configured in `components.json`

## Using Components

Import components from the ui directory using the configured aliases:

```tsx
import { Button } from "@/components/ui/button"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
```

Example usage:

```tsx
<Button variant="outline">Click me</Button>

<Card>
  <CardHeader>
    <CardTitle>Card Title</CardTitle>
    <CardDescription>Card Description</CardDescription>
  </CardHeader>
  <CardContent>
    <p>Card Content</p>
  </CardContent>
  <CardFooter>
    <p>Card Footer</p>
  </CardFooter>
</Card>
```

## Installing Additional Components

Many more components are available but not currently installed. You can view the complete list at https://ui.shadcn.com/r

To install additional components, use the Shadcn CLI:

```bash
npx shadcn@latest add [component-name]
```

For example, to add the Accordion component:

```bash
npx shadcn@latest add accordion
```

Note: `npx shadcn-ui@latest` is deprecated, use `npx shadcn@latest` instead

Some commonly used components are

- Accordion
- Alert
- AlertDialog
- AspectRatio
- Avatar
- Calendar
- Checkbox
- Collapsible
- Command
- ContextMenu
- DataTable
- DatePicker
- Dropdown Menu
- Form
- Hover Card
- Menubar
- Navigation Menu
- Popover
- Progress
- Radio Group
- ScrollArea
- Select
- Separator
- Sheet
- Skeleton
- Slider
- Switch
- Table
- Textarea
- Toast
- Toggle
- Tooltip

## Component Styling

This project uses the "new-york" style variant with the "neutral" base color and CSS variables for theming, as configured in `components.json`.
EOF

# Step 14: Open project in Cursor and provide instructions
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
echo -e "${GREEN}  ✅ Custom branding with project name (${PROJECT_NAME})${NC}"
echo -e "${GREEN}  ✅ Custom dice icon from GitHub repository${NC}"
echo -e "${GREEN}  ✅ All default React references replaced with project name${NC}"
echo -e "${GREEN}  ✅ Git repository initialization with comprehensive .gitignore${NC}"
echo -e "${GREEN}  ✅ Initial commit with project structure documentation${NC}"
echo ""
echo -e "${YELLOW}🚀 Opening project in Cursor...${NC}"

# Ensure we're inside the project directory before opening and starting
if [ -d "${PROJECT_NAME}" ]; then
  cd "${PROJECT_NAME}"
else
  echo -e "${YELLOW}⚠️  Project directory not found: ${PROJECT_NAME}. Using current directory: $(pwd)${NC}"
fi

# Open project in Cursor (background)
echo -e "${BLUE}📝 Opening ${PROJECT_NAME} in Cursor...${NC}"
nohup cursor . </dev/null >/dev/null 2>&1 &

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

echo -e "${YELLOW}🚀 Starting development server...${NC}"
npm run dev
