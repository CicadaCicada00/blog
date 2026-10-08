@echo off
set msg=%*
if "%msg%"=="" set msg=update

cd /d "C:\Users\LENOVO\Desktop\blog"
echo [1/4] Staging changes...
git add -A

echo [2/4] Checking for changes to commit...
git diff --cached --quiet
if %errorlevel% neq 0 (
    echo [3/4] Committing: "%msg%"
    git commit -m "%msg%"
) else (
    echo No new changes to commit. Proceeding to push...
)

echo [4/4] Pushing to GitHub (main and gh-pages)...
git push origin main
git push origin main:gh-pages
echo Done!
