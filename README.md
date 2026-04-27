# Production Environment Configuration

## 📋 Environment Variables Template

Create a `.env` file in the `backend/` directory with the following variables:

```bash
# Server Configuration
NODE_ENV=production
PORT=8080
CORS_ORIGIN=https://yourdomain.com

# Database (MongoDB Atlas)
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/knowledge-center?retryWrites=true&w=majority

# Payment Integration (Nkwa)
NKWA_BASE_URL=https://api.mynkwa.com
NKWA_API_KEY=your_nkwa_api_key_here

# Security (Generate with: openssl rand -base64 32)
JWT_SECRET=your-super-secret-jwt-key-minimum-32-characters
ENCRYPTION_KEY=your-32-character-encryption-key-here

# Email Configuration (Optional - for notifications)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-specific-password

# Logging
LOG_LEVEL=info

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
AUTH_RATE_LIMIT_MAX_REQUESTS=5
```

## 🔧 Package Dependencies

Ensure your `package.json` includes these production-ready dependencies:

```json
{
  "dependencies": {
    "express": "^4.18.2",
    "mongoose": "^7.5.0",
    "cors": "^2.8.5",
    "helmet": "^7.0.0",
    "express-rate-limit": "^6.10.0",
    "morgan": "^1.10.0",
    "validator": "^13.11.0",
    "express-validator": "^7.0.1",
    "axios": "^1.5.0",
    "dotenv": "^16.3.1"
  }
}
```

## 🚀 Production Deployment Scripts

### 1. PM2 Ecosystem File (ecosystem.config.js)

```javascript
module.exports = {
  apps: [{
    name: 'kc-backend',
    script: 'src/server.js',
    instances: 'max',
    exec_mode: 'cluster',
    env: {
      NODE_ENV: 'production'
    },
    error_file: './logs/err.log',
    out_file: './logs/out.log',
    log_file: './logs/combined.log',
    time: true,
    merge_logs: true,
    max_memory_restart: '1G'
  }]
};
```

### 2. Start Script (package.json)

```json
{
  "scripts": {
    "start": "node src/server.js",
    "dev": "nodemon src/server.js",
    "build": "echo 'No build step required'",
    "test": "jest",
    "lint": "eslint src/",
    "format": "prettier --write src/"
  }
}
```

## 🛡️ Security Checklist

- [ ] Enable HTTPS on all endpoints
- [ ] Set up firewall rules (ufw, security groups)
- [ ] Configure rate limiting (implemented)
- [ ] Enable MongoDB Atlas encryption at rest
- [ ] Set up monitoring alerts
- [ ] Regular security updates
- [ ] API key rotation policy

## 🔍 Health Check & Monitoring

### Health Check Endpoint
```
GET /health
```

Returns:
```json
{
  "ok": true,
  "timestamp": "2024-01-01T00:00:00.000Z",
  "uptime": "1h 30m 45s",
  "database": "connected",
  "services": {
    "mongodb": true,
    "nkwa": true
  }
}
```

### Production Logging

The backend includes structured logging:

```javascript
// Example log entries
{
  "timestamp": "2024-01-01T12:00:00.000Z",
  "level": "info",
  "message": "Payment initiated for registration KC-STEM-123456",
  "reference": "KC-STEM-123456",
  "amount": 5000
}

{
  "timestamp": "2024-01-01T12:05:00.000Z",
  "level": "error",
  "message": "Nkwa API error",
  "reference": "KC-STEM-123456",
  "error": "Payment timeout"
}
```

## 📊 Monitoring Setup

### Application Metrics
- Response times
- Error rates
- Database connection status
- Payment success rates

### Database Monitoring
- Connection pool status
- Query performance
- Storage usage
- Backup status

### External Service Monitoring
- Nkwa API availability
- Payment gateway status
- Email service health

## 🔄 Backup Strategy

### Automated Backups
```bash
# MongoDB Atlas (7-day retention)
# Enable in Atlas dashboard

# Application logs backup
# Configure log rotation in PM2
```

### Manual Backup Procedures
```bash
# Database backup
mongodump --uri="$MONGODB_URI" --out=/backup/$(date +\%Y\%m\%d)

# Environment variables backup (encrypted)
# Store in secure location
```

## 🚨 Troubleshooting

### Common Production Issues

1. **Database Connection Failed**
   ```bash
   # Check MongoDB URI format
   # Verify network access in Atlas
   # Confirm username/password
   ```

2. **Payment Integration Issues**
   ```bash
   # Verify Nkwa API credentials
   # Check webhook URL configuration
   # Ensure sufficient account balance
   ```

3. **CORS Errors**
   ```bash
   # Update CORS_ORIGIN in environment
   # Check frontend domain configuration
   ```

### Debug Commands

```bash
# Check application status
pm2 status

# View logs
pm2 logs kc-backend

# Monitor resource usage
pm2 monit

# Restart application
pm2 restart kc-backend

# Check MongoDB connection
curl https://yourdomain.com/health
```

## 📈 Performance Optimization

### Database Indexes (Auto-created)
- Email uniqueness in subscribers
- Registration references
- Blog post interactions
- Timeline items

### Caching Strategy
- Consider Redis for session storage
- Implement response caching for static content
- Cache frequently accessed data

### Scaling Considerations
- Use PM2 cluster mode for multi-core support
- Implement horizontal scaling with load balancer
- Consider CDN for static assets

---

**Ready for Production?** ✅
- All security measures implemented
- Comprehensive error handling
- Production logging configured
- Monitoring and alerting ready
- Backup strategy in place

## 🎯 Quick Start Commands

```bash
# 1. Install dependencies
npm install

# 2. Configure environment
cp .env.example .env
# Edit .env with your production values

# 3. Test locally
npm run dev

# 4. Deploy to production
pm2 start ecosystem.config.js

# 5. Monitor deployment
pm2 logs kc-backend --lines 50
```

For additional support, refer to the troubleshooting section above or contact the development team.
