# Siox LinkedIn Tracker Backend

Floor LinkedIn posting calendar for the Siox Transports team. Express + MongoDB Atlas.

## Local

```powershell
npm install
npm start
```

Open http://localhost:3000

Create a `.env` file (do not commit it):

```
PORT=3000
MONGODB_URI=mongodb+srv://USER:PASS@cluster0.xxxxx.mongodb.net/siox_linkedin?retryWrites=true&w=majority
JWT_SECRET=a-long-random-secret
```

## Deploy on Render (free)

1. In MongoDB Atlas → Network Access → allow `0.0.0.0/0`
2. [Render](https://render.com) → New → Web Service → this GitHub repo
3. Build: `npm install`
4. Start: `npm start`
5. Environment variables:
   - `MONGODB_URI` — Atlas connection string
   - `JWT_SECRET` — any long random string

Render sets `PORT` automatically.
