const mongoose = require('mongoose');
require('dotenv').config();

const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI, {
      serverSelectionTimeoutMS: 20000,
    });
    console.log("Conectado a MongoDB Atlas vía Mongoose");

    mongoose.connection.once('open', () => {
      console.log("La conexión de Mongoose está abierta");
    });
    mongoose.connection.on('error', (err) => {
      console.error("Error en la conexión de Mongoose:", err);
    });
  } catch (error) {
    console.error("Error al conectar a MongoDB:", error);
    process.exit(1);
  }
};

module.exports = { connectDB };
