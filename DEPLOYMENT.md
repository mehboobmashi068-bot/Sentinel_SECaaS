# Deployment Instructions (Railway)

To deploy this Sentinel OS SIEM project to Railway, follow these steps:

## 1. Prepare Your Environment Variables
In the Railway dashboard, add the following variables under the **Variables** tab:

### Required for All Deployments:
- `GEMINI_API_KEY`: Your Google Gemini API Key.
- `ADMIN_API_KEY`: A master key for authorized API access (default: `sk_master_777_sentinel`).
- `SENTINEL_DB_ENCRYPTION_KEY`: A random string for AES-256 encryption.

### Optional but Recommended:
- `VITE_GEMINI_API_KEY`: For AI-powered forensic analysis (overrides environment variable).

## 2. Configuration Details
- **Port**: The application is configured to use `process.env.PORT || 3000`. Railway will automatically provide the `PORT` variable.
- **Database**: The project uses **SQLite**. In production (Railway), the SQLite file (`ThreatVault.db`) will be stored in the ephemeral file system by default. For persistent storage, you should attach a **Volume** in Railway and update the path in `server.ts`.

## 3. Deployment Flow
1. Connect your GitHub repository to Railway.
2. Railway will detect the `package.json` and automatically run `npm run build` and then `npm start`.
3. Ensure the **Build Command** is set to `npm run build` and the **Start Command** is `npm start`.

## 4. Security Notes
- **CORS**: Configured to allow all origins by default. For higher security, restrict this to your actual production domain.
- **Helmet**: Security headers are enabled.
- **Rate Limiting**: Integrated based on IP and browser fingerprints.
