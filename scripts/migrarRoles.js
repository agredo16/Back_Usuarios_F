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
          'crear_clientes',
          'editar_clientes',
          'editar_laboratoristas',
          'gestionar_laboratoristas',
          'gestionar_clientes',
          'crear_laboratoristas' 
        ],
        description: 'Gestiona usuarios y tiene acceso a la mayoría de funciones administrativas.'
      },
      {
        name: 'laboratorista',
        permisos: [
          'ver_usuarios',
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
