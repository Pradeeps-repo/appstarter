# Full-Stack TypeScript Setup Script

   One-command setup for Express TypeScript + React + shadcn/ui projects.

   ## Quick Start

   ```bash
   curl -fsSL https://raw.githubusercontent.com/pradeeps-repo/appstarter/main/setup.sh | bash -s my-project-name
   ```

   ## What it creates
   - Express.js with TypeScript
   - React with TypeScript & shadcn/ui
   - MVC architecture
   - Concurrent development setup
   - Clean build organization

   ## Admin seed

   Generated apps do not include a default admin email or password. Setup skips the database seed when `ADMIN_EMAIL` or `ADMIN_PASSWORD` is empty. Running the seeder directly refuses to write unless both are set. The generated `.env.example` names those variables and leaves the values empty. Put real values in `.env` or the process environment, then run `npm run db:seed`.
