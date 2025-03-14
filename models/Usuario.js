require('dotenv').config();
const crypto = require('crypto');
const { ObjectId } = require("mongodb");
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const usuarioSchema = new mongoose.Schema({
  email: {
    type: String,
    unique: true,
    required: true,
    lowercase: true,
    trim: true
  },
  nombre: {
    type: String,
    required: true,
    trim: true
  },
  documento: {
    type: String,
    required: true,
    trim: true
  },
  telefono: {
    type: String,
    trim: true
  },
  direccion: {
    type: String,
    trim: true
  },
  password: {
    type: String,
    required: true
  },
  // Aquí se define el rol como una referencia al modelo Role
  rol: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Role',
    required: true
  },
  activo: {
    type: Boolean,
    default: true
  },
  detalles: {
    // Estos campos adicionales se mantienen según el tipo de usuario
    tipo: {
      type: String,
      enum: ['cliente']
      // no se especifica required, se define desde el front si es necesario
    },
    razonSocial: {
      type: String
    },
    especialidad: String,
    nivelAcceso: Number,
    codigoSeguridad: String,
    registroAcciones: [{
      accion: String,
      fecha: Date,
      detalles: String
    }],
    historialSolicitudes: []
  },
  fechaCreacion: {
    type: Date,
    default: Date.now,
    immutable: true
  },
  fechaActualizacion: Date
});

usuarioSchema.pre('findOneAndUpdate', function(next) {
  this.setOptions({ new: true, runValidators: true });
  this._update.fechaActualizacion = new Date();
  next();
});

// Se asume que, cuando se consulta un usuario, se usa .populate('rol')
// para tener acceso a rol.name y rol.permisos en los métodos
usuarioSchema.methods.tienePermiso = async function(permiso) {
  if (!this.rol) return false;
  if (this.rol.name === 'super_admin') return true;
  return this.rol.permisos.includes(permiso);
};

usuarioSchema.methods.puedeModificarUsuario = async function(usuarioObjetivoId) {
  if (!ObjectId.isValid(usuarioObjetivoId)) {
    throw new Error('ID de usuario no válido');
  }

  if (this._id.toString() === usuarioObjetivoId.toString()) {
    return true;
  }

  const usuarioObjetivo = await this.constructor.findById(usuarioObjetivoId).populate('rol');
  if (!usuarioObjetivo) {
    return false;
  }

  if (this.rol.name === 'super_admin') {
    return true;
  }

  if (this.rol.name === 'administrador') {
    return ['laboratorista'].includes(usuarioObjetivo.rol.name);
  }

  return false;
};

usuarioSchema.statics.obtenerPorEmail = async function(email) {
  return await this.findOne({ email }).populate('rol').exec();
};

usuarioSchema.statics.obtenerPorId = async function(id) {
  return await this.findById(id).populate('rol').exec();
};

usuarioSchema.statics.obtenerTodos = async function() {
  return await this.find({ activo: true })
    .select('-password -detalles')
    .exec();
};

usuarioSchema.statics.contarUsuarios = async function() {
  return await this.countDocuments({ activo: true });
};

usuarioSchema.statics.crear = async function(datos) {
  try {
    const nuevoUsuario = new this(datos);
    return await nuevoUsuario.save();
  } catch (error) {
    throw new Error(`Error al crear usuario: ${error.message}`);
  }
};

usuarioSchema.statics.actualizarUsuario = async function(id, datosActualizados, usuarioActual) {
  try {
    if (!ObjectId.isValid(id)) {
      throw new Error('ID de usuario inválido');
    }

    const usuario = await this.findById(id).populate('rol');
    if (!usuario) {
      throw new Error('Usuario no encontrado');
    }

    if (datosActualizados._id) {
      throw new Error('No se puede modificar el ID del usuario');
    }

    if (usuario._id.toString() !== usuarioActual.userId.toString() &&
        usuarioActual.rol !== 'super_admin') {
      throw new Error('No tiene permisos para modificar este usuario');
    }

    const resultado = await this.findByIdAndUpdate(
      id,
      datosActualizados,
      { new: true, runValidators: true }
    );

    return resultado;
  } catch (error) {
    console.error('Error al actualizar usuario:', error);
    throw new Error(`Error al actualizar usuario: ${error.message}`);
  }
};

usuarioSchema.statics.generarTokenRecuperacion = async function(email) {
  const usuario = await this.findOne({ email }).populate('rol');
  if (!usuario) {
    return {
      email: email,
      token: 'token-simulado',
      nombre: 'Usuario no encontrado'
    };
  }
  
  const token = crypto.randomBytes(20).toString('hex');
  
  usuario.tokenRecuperacion = {
    token: token,
    expiracion: Date.now() + 3600000,
    intentos: 0
  };
  
  await usuario.save();
  
  return {
    email: usuario.email,
    token: token,
    nombre: usuario.nombre
  };
};
usuarioSchema.statics.inicializarRoles = async function() {
    const Role = require('./Role'); // Asegúrate de que la ruta sea correcta
    // Verificar si existen usuarios con rol asignado
    const usuariosExistentes = await this.countDocuments({ rol: { $exists: true } });
    if (usuariosExistentes === 0) {
      // Buscar el rol super_admin en la colección de roles
      const rolSuperAdmin = await Role.findOne({ name: 'super_admin' });
      if (!rolSuperAdmin) {
        throw new Error('No se encontró el rol super_admin en la colección de roles');
      }
      await this.create({
        email: 'agredoyudith00@gmail.com',
        nombre: 'Yudith Agredo',
        documento: '1108334033',
        rol: rolSuperAdmin._id,
        password: await bcrypt.hash('admin123', 10),
        activo: true,
        detalles: {
          codigoSeguridad: '3403'
        },
        fechaCreacion: new Date()
      });
    }
  };

const Usuario = mongoose.model('Usuario', usuarioSchema);

module.exports = Usuario;
