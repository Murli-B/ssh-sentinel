# Publish SSH Sentinel to GitHub

This workspace has no connection to your GitHub account, so the files are prepared locally but have **not** been pushed to a live GitHub repository. These steps publish them without sharing an access token.

## Option A — GitHub CLI

1. Create or sign in to GitHub with the official CLI on your computer:

   ```bash
   gh auth login
   ```

2. From inside the `ssh-sentinel` folder, create the repository and push the files:

   ```bash
   gh repo create ssh-sentinel --public --source=. --remote=origin --push
   ```

   Choose `--private` instead of `--public` if you want a private repository.

## Option B — GitHub website and Git

1. On GitHub, choose **New repository** and name it `ssh-sentinel`.
2. Choose Public or Private. Leave **Add a README**, **.gitignore**, and **license** unchecked because this project already contains those files.
3. In a terminal opened in the project folder, run:

   ```bash
   git init -b main
   git add .
   git commit -m "Initial release: SSH Sentinel"
   git remote add origin https://github.com/YOUR-USERNAME/ssh-sentinel.git
   git push -u origin main
   ```

   Replace `YOUR-USERNAME` with your GitHub username. Git may prompt you to authenticate using GitHub's normal sign-in flow. **Never paste a password or personal access token into chat.**

After the first push, GitHub Actions will run the included tests. Replace the placeholder URL in the README's clone example if you use a different owner or repository name.
