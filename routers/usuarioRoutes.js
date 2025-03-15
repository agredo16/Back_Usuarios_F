const express = require('express');
const router = express.Router();
const { autenticar,verificarPermisos,loggin,manejarErrores } = require('../middlewares/middleware');
const Usuario = require('../models/Usuario');

module.exports = (autenticarMiddleware, usuarioModel) => {
    const UsuarioController = require('../controllers/usuarioController');
    const controller = new UsuarioController(usuarioModel);

    router.post('/login', (req, res) => controller.login(req, res));

    router.post('/registro', autenticarMiddleware, async (req, res, next) => {
        try {
            const rolAutenticado = req.usuario.rol; // Se espera que sea una cadena (por ejemplo, "super_admin", "administrador", etc.)
    
            if (rolAutenticado === 'super_admin' && req.body.tipo !== 'administrador') {
                return res.status(403).json({
                    error: 'Acceso denegado',
                    detalles: 'El super admin solo puede crear administradores'
                });
            }
    
            if (rolAutenticado === 'administrador' && !['laboratorista', 'cliente'].includes(req.body.tipo)) {
                return res.status(403).json({
                    error: 'Acceso denegado',
                    detalles: 'El administrador solo puede crear laboratoristas o clientes'
                });
            }
    
            if (rolAutenticado === 'laboratorista') {
                return res.status(403).json({
                    error: 'Acceso denegado',
                    detalles: 'El laboratorista no tiene permisos para crear usuarios'
                });
            }
    
            const totalUsuarios = await usuarioModel.contarUsuarios();
            if (totalUsuarios === 0) {
                if (req.body.tipo !== 'super_admin') {
                    return res.status(400).json({
                        error: 'El primer usuario debe ser un super administrador'
                    });
                }
                return controller.registrar(req, res);
            }
    
            return controller.registrar(req, res);
        } catch (error) {
            next(error);
        }
    });
    

    router.post('/solicitar-recuperacion', (req, res) => 
        controller.solicitarRecuperacion(req, res)
    );

    const rutasAutenticadas = [
        { 
            path: '/', 
            method: 'get', 
            handler: 'obtenerTodos',
            permisos: ['ver_usuarios'] 
        },
        { 
            path: '/:id', 
            method: 'get', 
            handler: 'obtenerPorId',
            permisos: ['ver_usuarios', 'perfil_propio'] 
        },
        { 
            path: '/:id', 
            method: 'put', 
            handler: 'actualizar',
            permisos: ['editar_usuarios', 'perfil_propio'] 
        },
        { 
            path: '/:id', 
            method: 'delete', 
            handler: 'eliminar',
            permisos: ['eliminar_usuarios', 'eliminar_laboratoristas'] 
        },
        { 
            path: '/:id/estado',  
            method: 'put', 
            handler: 'actualizarEstado',
            permisos: ['desactivar_usuarios'] 
        }
    ];

    rutasAutenticadas.forEach(ruta => {
        router[ruta.method](ruta.path, autenticarMiddleware, (req, res, next) => {
            if (ruta.permisos.includes('perfil_propio') && req.params.id) {
                if (req.usuario.userId.toString() === req.params.id.toString()) {
                    return controller[ruta.handler](req, res, next);
                }
            }
            verificarPermisos(ruta.permisos)(req, res, () => {
                controller[ruta.handler](req, res, next);
            });
        });
    });

    return router;
};