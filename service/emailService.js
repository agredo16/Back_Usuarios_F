const nodemailer = require('nodemailer');

class EmailService {
  constructor() {
    this.validateEnvironmentVariables();

    this.transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: parseInt(process.env.EMAIL_PORT),
      secure: process.env.EMAIL_SECURE === 'true',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
      },
      tls: {
        rejectUnauthorized: process.env.NODE_ENV === 'production'
      }
    });
  }

  validateEnvironmentVariables() {
    const requiredVars = [
      'EMAIL_HOST',
      'EMAIL_PORT',
      'EMAIL_SECURE',
      'EMAIL_USER',
      'EMAIL_PASSWORD',
      'FRONTEND_URL'
    ];

    const missingVars = requiredVars.filter(varName => !process.env[varName]);

    if (missingVars.length > 0) {
      throw new Error(`Variables de entorno faltantes: ${missingVars.join(', ')}`);
    }
  }

  async enviarEmailRecuperacion(destinatario, token, nombreUsuario) {
    try {
      // Asegurarse de que FRONTEND_URL no tenga una barra final
      const baseUrl = process.env.FRONTEND_URL.endsWith('/') 
        ? process.env.FRONTEND_URL.slice(0, -1) 
        : process.env.FRONTEND_URL;
      const urlRecuperacion = `${baseUrl}/restablecer-password?token=${encodeURIComponent(token)}`;

      const mailOptions = {
        from: `"Sistema de Laboratorio" <${process.env.EMAIL_USER}>`,
        to: destinatario,
        subject: "Recuperación de contraseña",
        text: `Hola ${nombreUsuario},\n\nPara restablecer tu contraseña, haz clic en el siguiente enlace:\n${urlRecuperacion}\n\nSi no has solicitado este cambio, por favor ignora este mensaje.`,
        html: `
          <!DOCTYPE html>
          <html lang="es">
            <head>
              <meta charset="UTF-8">
              <style>
                .container {
                  max-width: 600px;
                  margin: 0 auto;
                  padding: 20px;
                  font-family: Arial, sans-serif;
                }
                .button {
                  background-color: #007bff;
                  color: white;
                  padding: 10px 15px;
                  text-decoration: none;
                  border-radius: 5px;
                  display: inline-block;
                  margin-top: 10px;
                }
              </style>
            </head>
            <body>
              <div class="container">
                <h2>Restablecimiento de Contraseña</h2>
                <p>Estimado/a ${nombreUsuario},</p>
                <p>Hemos recibido tu solicitud para restablecer tu contraseña.</p>
                <p><a href="${urlRecuperacion}" class="button">Restablecer Contraseña</a></p>
                <p>Si no has solicitado este cambio, por favor ignora este mensaje.</p>
                <p>Saludos cordiales,<br>Sistema de Laboratorio</p>
              </div>
            </body>
          </html>
        `
      };

      const info = await this.transporter.sendMail(mailOptions);
      console.log('Email enviado:', info.response);
      return info;
    } catch (error) {
      console.error('Error al enviar email:', {
        message: error.message,
        code: error.code,
        response: error.response
      });
      throw error;
    }
  }
}

module.exports = EmailService;
