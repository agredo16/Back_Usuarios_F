require('dotenv').config();

module.exports = {
  jwtConfig: {
    secret: process.env.JWT_SECRET || 'clave_secreta_por_defecto',
    expiresIn: process.env.JWT_EXPIRES_IN || '24h'
  },
  emailConfig: {
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    secure: process.env.EMAIL_SECURE === 'true',
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD
}
};