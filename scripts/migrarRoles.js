require('dotenv').config();
const { MongoClient } = require('mongodb');
const uri = process.env.MONGODB_URI;
const Role = require('../models/Role');


async function migrarRoles() {
  const client = new MongoClient(uri);
  try {
    await client.connect();
    const db = client.db();
    const rolesCollection = db.collection('roles');

    // Inserta o actualiza cada rol
    const roles = [
      {
        name: 'super_admin',
        permisos: ['ver_usuarios', 'crear_administradores', 'desactivar_usuarios'],
        description: 'Permite realizar todas las acciones administrativas.'
      },
      {
        name: 'administrador',
        permisos: [
          'ver_usuarios',
          'crear_usuarios',
          'editar_usuarios',
          'eliminar_usuarios',
          'gestionar_laboratoristas',
          'gestionar_clientes',
          'crear_laboratoristas' // Agregado si lo necesitas
        ],
        description: 'Gestiona usuarios y tiene acceso a la mayoría de funciones administrativas.'
      },
      {
        name: 'laboratorista',
        permisos: [
          'perfil_propio',
          'gestionar_pruebas',
          'ver_resultados',
          'registro_muestras'
        ],
        description: 'Encargado de realizar pruebas y gestionar resultados.'
      },
      {
        name: 'cliente',
        permisos: [
          'perfil_propio',
          'ver_resultados',
          'solicitar_pruebas'
        ],
        description: 'Cliente que puede solicitar pruebas y ver sus resultados.'
      }
    ];

    for (const rol of roles) {
      await rolesCollection.updateOne(
        { name: rol.name },
        { $set: rol },
        { upsert: true }
      );
    }

    console.log('Migración de roles completada exitosamente');
  } catch (error) {
    console.error('Error en la migración:', error);
  } finally {
    await client.close();
  }
}

migrarRoles();
