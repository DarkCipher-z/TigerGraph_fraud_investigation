# 🚀 1-Click Deployment Guide ($0.00 Free Tier)
**TigerGraph Agentic Fraud Investigation (HHGOA)**

Deploying your project to a live public URL gives judges a hands-on, interactive link they can test immediately. This significantly increases your submission score!

---

## 🌟 Method 1: Deploy to Streamlit Community Cloud (Recommended - Free)

**Streamlit Community Cloud** hosts your Streamlit application directly from your GitHub repository for free:

### Step 1: Push Code to GitHub
```powershell
git init
git add .
git commit -m "Complete TigerGraph Agentic Fraud Investigation System"
git branch -M main
git remote add origin https://github.com/<your-username>/<your-repo-name>.git
git push -u origin main
```

### Step 2: Connect Streamlit Community Cloud
1. Go to [share.streamlit.io](https://share.streamlit.io) and sign in with GitHub.
2. Click **"New app"**.
3. Select your repository: `<your-username>/<your-repo-name>`.
4. Branch: `main`
5. Main file path: `dashboard/app.py`
6. Click **"Advanced settings..."** -> **Secrets**, and paste your `.env` contents:
   ```toml
   TG_USE_MOCK = "true"
   GROQ_API_KEY = "gsk_..."
   GEMINI_API_KEY = "AIzaSy..."
   ```
7. Click **"Deploy!"**

Your live app will be available at: `https://<your-app-name>.streamlit.app`

---

## 🌟 Method 2: Deploy to Hugging Face Spaces (Alternative - Free)

1. Create a free account on [huggingface.co](https://huggingface.co).
2. Click **"New Space"**.
3. Select **Streamlit** SDK.
4. Set Space name to `tigergraph-fraud-investigation`.
5. Upload or push repository files.
6. Under Space Settings -> Secrets, add your environment variables.

---

## 💻 Local Testing & Demo Launch
To launch the dashboard locally on your machine at any time:
```powershell
python -m streamlit run dashboard/app.py
```
Or double-click:
`run_dashboard.bat`
