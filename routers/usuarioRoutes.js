const express = require('express');
const router = express.Router();
const { autenticar,verificarPermisos,loggin,manejarErrores } = require('../middlewares/middleware');
const Usuario = require('../models/Usuario');
const UsuarioController=require("../controllers/usuarioController")

module.exports = (autenticarMiddleware, usuarioModel) => {

    const UsuarioController = require('../controllers/usuarioController');
    const controller = new UsuarioController(usuarioModel);

    router.post('/login', (req, res) => controller.login(req, res));
    router.get('/buscar', (req, res) => controller.buscarPorDocumento(req, res));
    router.get("/roles/:id", controller.obtenerRoles.bind(controller));    
    router.post('/registro', autenticarMiddleware, async (req, res, next) => {
   
       
        try {
            const rolAutenticado = req.usuario.rol; 
    
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
    router.post('/cambiar-contrasena', (req, res) => 
        controller.cambiarContrasena(req, res)
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
            permisos: ["editar_clientes","editar_laboratoristas", 'perfil_propio'] 
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
   /* router.get('/roles', autenticarMiddleware, (req, res, next) => {
        verificarPermisos(['ver_usuarios'])(req, res, () => {
            controller.obtenerRoles(req, res, next);
        });
    });*/

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