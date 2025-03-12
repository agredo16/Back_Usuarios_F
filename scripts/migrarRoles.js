require('dotenv').config();
const { MongoClient } = require('mongodb');
const uri = process.env.MONGODB_URI;

async function migrarRoles() {
    const client = new MongoClient(uri);
    try {
        await client.connect();
        const db = client.db();
        const usuariosCollection = db.collection('usuarios');
        
        await usuariosCollection.updateMany(
            { 'rol.nombre': 'super_admin' },
            { $set: { 'rol.permisos': ['ver_usuarios', 'crear_administradores', 'desactivar_usuarios'] } }
        );
        
        await usuariosCollection.updateMany(
            { 'rol.nombre': 'administrador' },
            { $set: { 'rol.permisos': ['ver_usuarios', 'crear_usuarios', 'editar_usuarios', 'eliminar_usuarios', 'gestionar_laboratoristas', 'gestionar_clientes'] } }
        );
        
        await usuariosCollection.updateMany(
            {},
            { $set: { activo: true } }
        );
        
        console.log('Migración completada exitosamente');
    } catch (error) {
        console.error('Error en la migración:', error);
    } finally {
        await client.close();
    }
}

migrarRoles();