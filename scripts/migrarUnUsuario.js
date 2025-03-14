require('dotenv').config();
const { MongoClient, ObjectId } = require('mongodb');
const uri = process.env.MONGODB_URI;

async function migrarUnUsuario() {
  const client = new MongoClient(uri);
  try {
    await client.connect();
    const db = client.db();

    // 1. Buscar el documento de rol "super_admin"
    const superAdminRole = await db.collection('roles').findOne({ name: 'super_admin' });
    if (!superAdminRole) {
      console.log("No se encontró el rol super_admin en la colección 'roles'");
      return;
    }

    // 2. Definir el _id del usuario que quieres migrar
    const userId = "67ca0e3775f95ba3d231ea53";

    // 3. Eliminar el objeto 'rol' viejo
    await db.collection('usuarios').updateOne(
      { _id: new ObjectId(userId) },
      { $unset: { rol: "" } }
    );

    // 4. Asignar el ObjectId del rol al campo 'rol'
    await db.collection('usuarios').updateOne(
      { _id: new ObjectId(userId) },
      { $set: { rol: superAdminRole._id } }
    );

    console.log("Usuario migrado con éxito");
  } catch (err) {
    console.error("Error al migrar usuario:", err);
  } finally {
    await client.close();
  }
}

migrarUnUsuario();
