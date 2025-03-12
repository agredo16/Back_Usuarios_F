// models/Usuario.js
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
    rol: {
        nombre: {
            type: String,
            required: true,
            enum: ['super_admin', 'administrador', 'laboratorista','cliente'],
        },
        permisos: [String]
    },
    activo: {
        type: Boolean,
        default: true
    },
    detalles: {
        tipo: {
            type: String,
            enum: ['cliente'],
            required: function() {
                return this.rol.nombre === 'cliente';
            }
        },
        razonSocial: {
            type: String,
            required: function() {
                return this.rol.nombre === 'cliente';
            }
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

usuarioSchema.methods.tienePermiso = async function(permiso) {
    if (!this.rol) return false;
    if (this.rol.nombre === 'super_admin') return true;
    return this.rol.permisos.includes(permiso);
};

usuarioSchema.methods.puedeModificarUsuario = async function(usuarioObjetivoId) {
    if (!ObjectId.isValid(usuarioObjetivoId)) {
        throw new Error('ID de usuario no válido');
    }

    if (this._id.toString() === usuarioObjetivoId.toString()) {
        return true;
    }

    const usuarioObjetivo = await this.constructor.findById(usuarioObjetivoId);
    if (!usuarioObjetivo) {
        return false;
    }

    if (this.rol.nombre === 'super_admin') {
        return true;
    }

    if (this.rol.nombre === 'administrador') {
        return ['laboratorista'].includes(usuarioObjetivo.rol.nombre);
    }

    return false;
};

usuarioSchema.statics.obtenerRolesCache = async function() {
    const ahora = Date.now();
    if (!this.rolesCache || (ahora - this.ultimaActualizacionRoles) > this.INTERVALO_CACHE) {
        this.rolesCache = await this.find({}, 'rol.nombre rol.permisos').exec();
        this.ultimaActualizacionRoles = ahora;
    }
    return this.rolesCache;
};

usuarioSchema.statics.inicializarRoles = async function() {
    const rolesExistentes = await this.countDocuments({ 'rol.nombre': { $exists: true } });
    if (rolesExistentes === 0) {
        await this.create({
            email: 'admin@ejemplo.com',
            nombre: 'Administrador',
            documento: '123456789',
            rol: {
                nombre: 'super_admin',
                permisos: ['ver_usuarios', 'crear_administradores', 'desactivar_usuarios']
            },
            password: await bcrypt.hash('admin123', 10),
            detalles: {
                codigoSeguridad: 'codigo-seguridad'
            }
        });
    }
};

usuarioSchema.statics.obtenerPermisosPorTipo = function(tipo) {
    const permisos = {
        super_admin: [
            'ver_usuarios',
            'crear_administradores',
            'desactivar_usuarios'
        ],
        administrador: [
            'ver_usuarios',
            'crear_usuarios',
            'editar_usuarios',
            'eliminar_usuarios',
            'gestionar_laboratoristas',
            'gestionar_clientes'
        ],
        laboratorista: [
            'perfil_propio',
            'gestionar_pruebas',
            'ver_resultados',
            'registro_muestras'
        ],
        cliente: [
            'perfil_propio',
            'ver_resultados',
            'solicitar_pruebas'
        ]
    };
    return permisos[tipo] || [];
};

usuarioSchema.statics.obtenerPorEmail = async function(email) {
    return await this.findOne({ email }).exec();
};
usuarioSchema.statics.obtenerPorId = async function(id) {
    return await this.findById(id).exec();
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

        const usuario = await this.findById(id);
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
            { 
                new: true,
                runValidators: true 
            }
        );

        return resultado;
    } catch (error) {
        console.error('Error al actualizar usuario:', error);
        throw new Error(`Error al actualizar usuario: ${error.message}`);
    }
};
usuarioSchema.statics.generarTokenRecuperacion = async function(email) {
    const usuario = await this.findOne({ email });
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
const Usuario = mongoose.model('Usuario', usuarioSchema);

module.exports = Usuario;