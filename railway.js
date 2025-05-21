{
  "build": {
    "builder": "nixpacks"
  },
  "deploy": {
    "startCommand": "gunicorn main:app",
    "healthcheckPath": "/",
    "healthcheckTimeout": 300,
    "restartPolicyType": "on-failure",
    "restartPolicyMaxRetries": 10
  },
  "variables": {
    "PORT": "8080"
  }
}
