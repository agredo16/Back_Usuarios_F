const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const Usuario = require('../models/Usuario');
const emailService = require('../service/emailService');
const config = require('../config/database');
const EmailService = require('../service/emailService');
const Role = require('../models/Role');

class UsuarioController {
    constructor(usuarioModel) {
        this.usuarioModel = usuarioModel;
        this.emailService = new EmailService();
        console.log('UsuarioController inicializado con modelo:', this.usuarioModel);
    }

    obtenerPermisosPorTipo(tipo) {
        const permisos = {
            super_admin: [
                'ver_usuarios',
                'crear_administradores',
                'desactivar_usuarios'
            ],
            administrador: [
                'ver_usuarios',
                'crear_laboratoristas',
                'crear_clientes',
                'editar_clientes',
                'editar_laboratoristas',
                'gestionar_laboratoristas',
                'gestionar_clientes'
            ],
            laboratorista: [
                'perfil_propio',
                'gestionar_pruebas',
                'ver_resultados',
                'registro_muestras'
            ]
        };
        return permisos[tipo] || [];
    }

    async registrar(req, res) {
        try {
          const { email, password, nombre, tipo, documento, telefono, direccion, ...datosEspecificos } = req.body;
            
          if (!tipo || !['super_admin', 'administrador', 'laboratorista', 'cliente'].includes(tipo)) {
            return res.status(400).json({
              error: 'Tipo de usuario inválido',
              detalles: 'Los tipos permitidos son: super_admin, administrador, laboratorista, cliente'
            });
          }
      
          const totalUsuarios = await this.usuarioModel.contarUsuarios();
          if (totalUsuarios === 0) {
            if (tipo !== 'super_admin') {
              return res.status(400).json({
                error: 'El primer usuario debe ser un super administrador'
              });
            }
          }
      
          const existente = await this.usuarioModel.obtenerPorEmail(email);
          if (existente) {
            return res.status(400).json({
              error: 'Email ya registrado',
              detalles: 'El email proporcionado ya está en uso'
            });
          }
      
          const hashedPassword = await bcrypt.hash(password, 10);
      
          const Role = require('../models/Role');
          const rolEncontrado = await Role.findOne({ name: tipo });
          if (!rolEncontrado) {
            return res.status(400).json({ error: 'Rol no encontrado' });
          }
      
          const nuevoUsuario = {
            email,
            password: hashedPassword,
            nombre,
            documento,
            telefono,
            direccion,
            fechaCreacion: new Date(),
            activo: true,
            rol: rolEncontrado._id, 
            detalles: {}
          };
      
          switch (tipo) {
            case 'laboratorista':
              nuevoUsuario.detalles = {
                especialidad: datosEspecificos?.especialidad || '',
                ...datosEspecificos
              };
              break;
            case 'administrador':
              nuevoUsuario.detalles = {
                nivelAcceso: datosEspecificos?.nivelAcceso || 1,
                ...datosEspecificos
              };
              break;
            case 'super_admin':
              nuevoUsuario.detalles = {
                codigoSeguridad: datosEspecificos?.codigoSeguridad,
                registroAcciones: [],
                ...datosEspecificos
              };
              break;
            case 'cliente':
              nuevoUsuario.detalles = {
                tipo: "cliente",
                razonSocial: datosEspecificos?.razonSocial || ""
              };
              break;
          }
      
          const resultado = await this.usuarioModel.crear(nuevoUsuario);
          return res.status(201).json({
            mensaje: 'Usuario creado exitosamente',
            usuario: {
              _id: resultado.insertedId,
              email,
              nombre,
              tipo
            }
          });
        } catch (error) {
          console.error('Error en el registro:', error);
          res.status(500).json({ 
            error: 'Error en el servidor', 
            detalles: error.message 
          });
        }
      }
      

    async login(req, res) {
        try {
            const { email, password } = req.body;
            const usuario = await this.usuarioModel.obtenerPorEmail(email);
            console.log('Usuario obtenido:', usuario);

            if (!usuario) {
                return res.status(400).json({
                    error: 'Credenciales inválidas',
                    detalles: 'Email no encontrado'
                });
            }

            if (!usuario.activo) {
                return res.status(400).json({
                    error: 'Usuario inactivo',
                    detalles: 'El usuario está desactivado'
                });
            }

            const contraseñaValida = await bcrypt.compare(password, usuario.password);
            if (!contraseñaValida) {
                return res.status(400).json({
                    error: 'Credenciales inválidas',
                    detalles: 'Contraseña incorrecta'
                });
            }

            const payload = {
                userId: usuario._id,
                email: usuario.email,
                nombre: usuario.nombre,
                rol: usuario.rol.name,
                permisos: usuario.rol.permisos || []
            };

            const token = jwt.sign(payload, config.jwtConfig.secret, { expiresIn: config.jwtConfig.expiresIn });
            return res.status(200).json({
                mensaje: 'Login exitoso',
                token,
                usuario: {
                    _id: usuario._id,
                    nombre: usuario.nombre,
                    email: usuario.email,
                    rol: usuario.rol.name,
                    permisos: usuario.rol.permisos || []
                }
            });
        } catch (error) {
            res.status(500).json({ error: 'Error en el servidor', detalles: error.message });
        }
    }

    async obtenerTodos(req, res) {
        try {
            const usuarios = await this.usuarioModel.obtenerTodos();
            res.status(200).json(usuarios);
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    }

    async obtenerPorId(req, res) {
        try {
            const usuario = await this.usuarioModel.obtenerPorId(req.params.id);
            if (!usuario) {
                return res.status(404).json({ error: 'Usuario no encontrado' });
            }
            const { password, ...usuarioSinPassword } = usuario;
            res.status(200).json(usuarioSinPassword);
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    }

    async actualizar(req, res) {
        try {
          console.log('Datos recibidos en el controlador:', {
            body: req.body,
            usuario: req.usuario,
            id: req.params.id
          });
          
          console.log('Campos específicos a actualizar:', {
            nombre: req.body.nombre,
            documento: req.body.documento,
            telefono: req.body.telefono,
            email: req.body.email,
            rol: req.body.rol
          });
          const usuarioActual = req.usuario;
          
          const puedeModificar = await this.usuarioModel.puedeModificarUsuario(req.params.id);
          if (!puedeModificar) {
            return res.status(403).json({
              error: 'Acceso denegado',
              detalles: 'No tiene permisos para modificar este usuario'
            });
          }
          
          const { password, tipo, rol, ...datosActualizados } = req.body;
      
          if (password) {
            datosActualizados.password = await bcrypt.hash(password, 10);
          }
      
          if (tipo && usuarioActual.rol !== 'super_admin') {
            return res.status(403).json({
              error: 'No tiene permisos para modificar el tipo de usuario'
            });
          }

          if (rol && usuarioActual.rol !== 'super_admin') {
            return res.status(403).json({
              error: 'No tiene permisos para modificar el rol del usuario'
            });
          }

          if (rol) {
            try {
              const Role = require('../models/Role');
              const rolEncontrado = await Role.findOne({ name: rol });
              if (!rolEncontrado) {
                return res.status(400).json({ error: 'Rol no encontrado' });
              }
              datosActualizados.rol = rolEncontrado._id;
            } catch (error) {
              return res.status(500).json({ 
                error: 'Error al buscar el rol',
                detalles: error.message 
              });
            }
          }
      
          console.log('Datos que se enviarán para actualización:', datosActualizados);
          
          const resultado = await this.usuarioModel.actualizarUsuario(
            req.params.id,
            datosActualizados,
            usuarioActual
          );
          
          console.log('Resultado de la actualización:', resultado);
          
          const usuarioActualizado = await this.usuarioModel.obtenerPorId(req.params.id);
          
          if (!usuarioActualizado) {
            return res.status(404).json({
              error: 'Usuario no encontrado después de la actualización',
              detalles: 'No se pudo recuperar la información actualizada'
            });
          }

          res.status(200).json({
            mensaje: 'Usuario actualizado exitosamente',
            usuario: {
              _id: usuarioActualizado._id,
              email: usuarioActualizado.email,
              nombre: usuarioActualizado.nombre,
              documento: usuarioActualizado.documento,
              telefono: usuarioActualizado.telefono,
              tipo: usuarioActualizado.rol.name,
              rol: {
                id: usuarioActualizado.rol._id,
                nombre: usuarioActualizado.rol.name
              },
              activo: usuarioActualizado.activo
            }
          });
      
        } catch (error) {
          console.error('Error en la actualización:', error);
          res.status(500).json({ 
            error: 'Error en el servidor', 
            detalles: error.message 
          });
        }
      }
      
  async actualizarEstado(req, res) {
    try {
        const { id } = req.params;
        console.log("actualizarEstado - req.params.id:", id);
        const { activo } = req.body;
        console.log("actualizarEstado - req.body:", req.body);
  
        const resultado = await this.usuarioModel.actualizarUsuario(
            id,
            { activo },
            req.usuario
        );
        console.log("actualizarEstado - resultado de actualizarUsuario:", resultado);
        
        if (!resultado) {
            console.log("actualizarEstado - Usuario no encontrado para id:", id);
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }
  
        res.status(200).json({ mensaje: `Usuario ${activo ? 'activado' : 'desactivado'} exitosamente` });
    } catch (error) {
        console.error("actualizarEstado - Error:", error);
        res.status(500).json({ error: 'Error en el servidor', detalles: error.message });
    }
  }

  async desactivarUsuario(req, res) {
    try {
        const { id } = req.params;
        const resultado = await this.usuarioModel.actualizarUsuario(
            id,
            { activo: false },
            req.usuario
        );

        if (resultado.matchedCount === 0) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }

        res.status(200).json({ mensaje: 'Usuario desactivado exitosamente' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
}

    async solicitarRecuperacion(req, res) {
        try {
            const { email } = req.body;
            if (!email) {
                return res.status(400).json({
                    error: 'Se requiere un correo electrónico',
                    detalles: 'Por favor proporcione un email valido'
                });
            }

            const resultado = await this.usuarioModel.generarTokenRecuperacion(email);
            try {
                await this.emailService.enviarEmailRecuperacion(
                    resultado.email,
                    resultado.token,
                    resultado.nombre
                );
            } catch (emailError) {
                console.log('Error al enviar email:', emailError);
                return res.status(500).json({
                    error: 'Error al enviar email de recuperación',
                    detalles: 'Por favor intente nuevamente más tarde'
                });
            }

            return res.status(200).json({
                mensaje: 'Si el correo existe en nuestra base de datos, recibirás instrucciones para restablecer tu contraseña',
                detalles: 'El enlace de recuperación es válido por 1 hora y tiene un maximo de 3 intentos'
            });
        } catch (error) {
            return res.status(400).json({
                error: error.message,
                detalles: 'Por favor, verifica tu email e intenta nuevamente'
            });
        }
    }
}

module.exports = UsuarioController;