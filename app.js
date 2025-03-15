require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const cors = require('cors');
const { connectDB } = require('./config/mongoose');
const usuarioRoutes = require('./routers/usuarioRoutes');
const Usuario = require('./models/Usuario');
const { autenticar } = require('./middlewares/middleware');
const emailService = require('./service/emailService');

const app = express();

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", 'data:'],
            upgradeInsecureRequests: []
        }
    },
    crossOriginResourcePolicy: { policy: 'cross-origin' },
    crossOriginEmbedderPolicy: false,
    originAgentCluster: true,
    referrerPolicy: { policy: 'same-origin' }
}));

app.use(compression());
app.use(express.json());
app.use(cors());

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 1000000, 
    standardHeaders: true,
    legacyHeaders: false,
});
app.use(limiter);

app.use((req, res, next) => {
    const fecha = new Date().toISOString();
    const metodo = req.method;
    const url = req.originalUrl || req.url;
    const ip = req.ip || req.connection.remoteAddress;
    console.log(`[${fecha}] ${metodo} ${url} - IP: ${ip}`);
    req.tiempoInicio = Date.now();
    res.on('finish', () => {
        const duracion = Date.now() - req.tiempoInicio;
        const statusCode = res.statusCode;
        console.log(`[${fecha}] ${metodo} ${url} - Estado: ${statusCode} - Duración: ${duracion}ms`);
    });
    next();
});

app.use((err, _req, res, next) => {
    console.error('Error en la aplicación:', err);
    if (err.statusCode) {
        return res.status(err.statusCode).json({
            error: err.message || 'Error en la aplicación',
            detalles: process.env.NODE_ENV === 'development' ? err.stack : undefined
        });
    }
    if (err.name === 'ValidationError') {
        return res.status(400).json({
            error: 'Error de validación',
            detalles: err.message
        });
    }
    if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
        return res.status(401).json({
            error: 'Error de autenticación',
            detalles: err.message
        });
    }
    res.status(500).json({
        error: 'Error interno del servidor',
        mensaje: err.message,
        detalles: process.env.NODE_ENV === 'development' ? err.stack : undefined
    });
});

async function iniciarServidor() {
    try {
        await connectDB();
        console.log('Conectado a Mongodb');
        
       // await Usuario.inicializarRoles();
        const autenticarMiddleware = autenticar(Usuario);
        
        // Rutas protegidas
        app.use('/api/usuarios', usuarioRoutes(autenticarMiddleware, Usuario));
        
        const PORT = process.env.PORT || 4000;
        app.listen(PORT, () => {
            console.log(`Servidor corriendo en puerto ${PORT}`);
        });
    } catch (error) {
        console.error('Error al iniciar el servidor:', error);
        process.exit(1);
    }
}

iniciarServidor();
