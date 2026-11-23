@echo off
setlocal
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
  echo ERROR: Install Node.js 22 LTS and reopen this window.
  pause
  exit /b 1
)
where npm >nul 2>nul
if errorlevel 1 (
  echo ERROR: npm is missing.
  pause
  exit /b 1
)
if not exist ".env" copy ".env.example" ".env" >nul
echo Installing or updating project dependencies. Internet access is required the first time.
call npm install
if errorlevel 1 (
  echo ERROR: npm install failed. Check internet, Node version and npm log.
  pause
  exit /b 1
)
echo Open http://localhost:3000 in your browser after server starts.
start "" "http://localhost:3000"
call npm run dev
pause
