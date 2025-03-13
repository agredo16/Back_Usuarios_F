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
            const totalUsuarios = await usuarioModel.contarUsuarios();
            if (totalUsuarios === 0) {
                if (req.body.tipo !== 'super_admin') {
                    return res.status(400).json({
                        error: 'El primer usuario debe ser un super administrador'
                    });
                }
                return controller.registrar(req, res);
            }

            const permisosRequeridos = {
                laboratorista: ['crear_laboratoristas'],
                administrador: ['crear_usuarios', 'crear_administradores'],
                cliente: ['gestionar_clientes']
            }[req.body.tipo];

            return verificarPermisos(permisosRequeridos)(req, res, () => 
                controller.registrar(req, res)
            );
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
            path: '/:id/desactivar', 
            method: 'put', 
            handler: 'desactivarUsuario',
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