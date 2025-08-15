# Base44 Secure Proxy (Node.js + Express)

A secure, production-ready proxy server for accessing the **Base44 API** without exposing your API key in the frontend.

---

## 🚀 Features
- **Keeps API keys secret** — uses `.env` file and server-side requests
- **CORS + Helmet** for security
- **Rate limiting** to prevent abuse
- **Input validation** using [Zod](https://github.com/colinhacks/zod)
- **Pagination, sorting, and filtering**
- **Centralized error handling**
- **Health check endpoint**

---

## 📦 Requirements
- [Node.js 16+](https://nodejs.org/) (LTS recommended)
- A [Base44 API Key](https://app.base44.com/)
- Git (for version control)

---

## 🛠 Installation

Clone your repository:
```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPO.git
cd base44-secure-proxy
