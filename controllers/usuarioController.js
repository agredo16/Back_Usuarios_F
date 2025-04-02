const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
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

    validarFortalezaContraseña(password) {
      const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
      return regex.test(password);
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
               'ver_usuarios',
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
          
          if (req.params.id) {
            if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
                return res.status(400).json({
                    error: 'ID inválido',
                    detalles: 'El ID proporcionado no es un ObjectId válido'
                });
            }
        }  

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
          if (!this.validarFortalezaContraseña(password)) {
            return res.status(400).json({
                error: 'Contraseña débil',
                detalles: 'La contraseña debe tener al menos 8 caracteres, incluir una mayúscula, un número y un caracter especial'
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
          // Validar ObjectId primero
          if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
              return res.status(400).json({ 
                  error: 'ID inválido',
                  detalles: 'El formato del ID no es válido'
              });
          }
  
          // Obtener usuario con populate y convertir a objeto plano
          const usuario = await this.usuarioModel.obtenerPorId(req.params.id)
              .then(u => u?.populate('rol'))
              .then(u => u?.toObject()) || null;
  
          if (!usuario) {
              return res.status(404).json({ 
                  error: 'Usuario no encontrado',
                  detalles: `No existe usuario con ID ${req.params.id}`
              });
          }
  
          // Eliminar campos sensibles y formatear respuesta
          const { password, tokenRecuperacion, __v, ...usuarioSeguro } = usuario;
          
          // Asegurar estructura consistente del rol
          if (usuarioSeguro.rol && typeof usuarioSeguro.rol === 'object') {
              usuarioSeguro.rol = {
                  id: usuarioSeguro.rol._id,
                  nombre: usuarioSeguro.rol.name,
                  permisos: usuarioSeguro.rol.permisos || []
              };
          }
  
          res.status(200).json(usuarioSeguro);
      } catch (error) {
          console.error(`Error al obtener usuario ${req.params.id}:`, error);
          res.status(500).json({ 
              error: 'Error interno del servidor',
              detalles: process.env.NODE_ENV === 'development' 
                  ? error.message 
                  : 'Por favor contacte al administrador'
          });
      }
  }

  async actualizar(req, res) {
    try {
        const id = req.params.id;
        
        // Validación de ID
        if (!mongoose.Types.ObjectId.isValid(id)) {
            return res.status(400).json({ 
                error: 'ID inválido',
                detalles: 'El formato del ID no es válido'
            });
        }

        // Verificar si el usuario existe
        const usuarioExiste = await Usuario.exists({ _id: id });
        if (!usuarioExiste) {
            return res.status(404).json({ 
                error: 'Usuario no encontrado',
                detalles: `El usuario con ID ${id} no existe`
            });
        }

        // Obtener usuario autenticado y usuario objetivo
        const usuarioActual = req.usuario; // El middleware ya asigna el usuario completo
        const usuarioObjetivo = await Usuario.findById(id).populate('rol').lean();

        // Validar permisos de edición
        const miRol = usuarioActual.rol.name.toLowerCase();
        const rolObjetivo = usuarioObjetivo.rol.name.toLowerCase();
        
        // Lógica de verificación de permisos (simplificada)
        if (miRol === 'super_admin' && rolObjetivo !== 'administrador') {
            return res.status(403).json({
                error: 'Acceso denegado',
                detalles: 'Super admin solo puede editar administradores'
            });
        }

        if (miRol === 'administrador' && !['cliente', 'laboratorista'].includes(rolObjetivo)) {
            return res.status(403).json({
                error: 'Acceso denegado',
                detalles: 'Administradores solo pueden editar clientes y laboratoristas'
            });
        }

        // Preparar datos para actualización
        const { password, ...datosActualizados } = req.body;
        
        if (password) {
            if (!this.validarFortalezaContraseña(password)) {
                return res.status(400).json({
                    error: 'Contraseña débil',
                    detalles: 'La contraseña debe tener al menos 8 caracteres, incluyendo mayúsculas, números y caracteres especiales'
                });
            }
            datosActualizados.password = await bcrypt.hash(password, 10);
        }

        // Realizar actualización
        const resultado = await Usuario.findByIdAndUpdate(
            id,
            datosActualizados,
            { 
                new: true,
                runValidators: true,
                populate: {
                    path: 'rol',
                    select: '_id name permisos'
                }
            }
        );

        if (!resultado) {
            return res.status(500).json({
                error: 'Error interno',
                detalles: 'No se pudo actualizar el usuario'
            });
        }

        // Formatear respuesta
        const respuesta = {
            _id: resultado._id,
            email: resultado.email,
            nombre: resultado.nombre,
            documento: resultado.documento,
            telefono: resultado.telefono,
            direccion: resultado.direccion,
            activo: resultado.activo,
            rol: {
                id: resultado.rol._id,
                nombre: resultado.rol.name,
                permisos: resultado.rol.permisos || []
            },
            detalles: resultado.detalles,
            fechaActualizacion: resultado.fechaActualizacion
        };

        return res.status(200).json({
            mensaje: 'Usuario actualizado exitosamente',
            usuario: respuesta
        });

    } catch (error) {
        console.error('Error en actualización:', error);
        
        if (error.name === 'ValidationError') {
            return res.status(400).json({
                error: 'Error de validación',
                detalles: error.message
            });
        }

        return res.status(500).json({
            error: 'Error interno del servidor',
            detalles: process.env.NODE_ENV === 'development' 
                ? error.message 
                : 'Por favor contacte al administrador'
        });
    }
}
  
  async verificarPermisosEdicion(rolActual, rolObjetivo) {
      if (rolActual === 'super_admin') {
          return true;
      }
      
      if (rolActual === 'administrador') {
          return ['cliente', 'laboratorista'].includes(rolObjetivo);
      }
      
      return false;
  }
    
      
  async actualizarEstado(req, res) {
    try {
        const { id } = req.params;
        console.log("actualizarEstado - req.params.id:", id);
        const { activo } = req.body;
        console.log("actualizarEstado - usuario autenticado:", req.usuario);
  
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
async cambiarContrasena(req, res) {
  try {
      const { token, password } = req.body;
      if (!token || !password) {
          return res.status(400).json({
              error: "Faltan datos",
              detalles: "Token y nueva contraseña son requeridos"
          });
      }

      if (!this.validarFortalezaContraseña?.(password)) {
          return res.status(400).json({
              error: "Contraseña débil",
              detalles: "La contraseña debe tener al menos 8 caracteres, incluir una mayúscula, un número y un caracter especial"
          });
      }

      const usuario = await this.usuarioModel.validarTokenRecuperacion(token);
      if (!usuario) {
          return res.status(400).json({
              error: "Token inválido o expirado",
              detalles: "El token no es válido o ya ha sido usado"
          });
      }

      const passwordEncriptada = await bcrypt.hash(password, 10);
      const resultado = await this.usuarioModel.actualizarContrasena(usuario.id, passwordEncriptada);

      if (!resultado.success) {
          return res.status(400).json({
              error: "No se pudo actualizar la contraseña",
              detalles: resultado.message
          });
      }

      return res.status(200).json({
          mensaje: "Contraseña actualizada con éxito",
          success: true
      });

  } catch (error) {
      console.error('Error en el cambio de contraseña:', error);
      return res.status(500).json({
          error: "Error interno del servidor",
          detalles: error.message
      });
  }

}

async obtenerRoles(req, res) {
  try {
      const { id } = req.params;  

      if (!id) {
          return res.status(400).json({ error: 'Se requiere un ID de usuario' });
      }

      const usuario = await Usuario.findById(id).populate("rol","_id name");

      if (!usuario) {
          return res.status(404).json({ error: 'Usuario no encontrado' });
      }

      const usuarioObj = usuario.toObject();
      delete usuarioObj.password;

     return res.status(200).json(usuarioObj);
  } catch (error) {
      res.status(500).json({ error: error.message });
  }
}

async buscarPorDocumento(req, res) {
  try {
    const { documento } = req.query;
    
    if (!documento) {
      return res.status(400).json({ error: 'Se requiere un número de documento para la búsqueda' });
    }

    const usuario = await Usuario.findOne({ documento }).populate('rol', '_id name');

    if (!usuario) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }
    
    if (usuario.rol.name.toLowerCase() !== 'cliente') {
      return res.status(403).json({ error: 'Acceso denegado, solo se permite la búsqueda de clientes' });
    }

    const usuarioObj = usuario.toObject();
    delete usuarioObj.password;

    res.status(200).json(usuarioObj);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
}



  
}
module.exports = UsuarioController;