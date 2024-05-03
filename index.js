const express = require("express");
const path = require("path");
const cors = require("cors");
const mysql = require("mysql");
const ejs = require("ejs");
const session = require('express-session');
const bcrypt = require('bcrypt');


const app = express();

app.use(express.json());
app.use(express.urlencoded({extended:false}));
app.use('/css', express.static(path.join(__dirname, 'css')));
app.use('/img', express.static(path.join(__dirname, 'img')));
app.use('/js', express.static(path.join(__dirname, 'js')));

app.engine('html', ejs.renderFile);
app.set("view engine", 'html');
app.use(session({
    secret: 'my-secret',
    resave: true,
    saveUninitialized: true
}));

const conexion = mysql.createConnection({
    host: "localhost",
    database: "login_register_db",
    user: "root",
    password: ""
});

app.get("/", function(req,res){
    res.sendFile(path.join(__dirname, '/html/index.html'));
});

app.get("/html/inicio_sesion.html", function(req, res) {
    res.sendFile(path.join(__dirname, '/html/inicio_sesion.html'), { mensajeError: false, mensajeSuccess: false});
});

app.post("/crear-usuario", function(req, res){
    const datos = req.body;
    const dni = datos.dni;
    const password = datos.password;

    // Hash de la contraseña
    bcrypt.hash(password, 10, function(err, hash) {
        if (err) {
            res.status(500).send("Error interno al crear usuario");
            return;
        }

        const buscar = "SELECT * FROM tabla_usuarios WHERE dni = ?";
        conexion.query(buscar, [dni], function(error, rows){
            if(error){
                res.status(500).send("Error interno al buscar usuario");
                return;
            }
            if(rows.length > 0){
                res.render(path.join(__dirname, 'html', 'registro.html'), {mensajeError: 'No se puede registrar, usuario ya existe', mensajeSuccess: false});
            } else {
                const registrar = "INSERT INTO tabla_usuarios(dni, password) VALUES(?, ?)";
                conexion.query(registrar, [dni, hash], function(error){
                    if(error){
                        res.status(500).send("Error interno al registrar usuario");
                        return;
                    }
                    res.render(path.join(__dirname, 'html', 'registro.html'), {mensajeSuccess: 'Se ha registrado con éxito', mensajeError: false});
                });
            }
        });
    });
});

app.post("/iniciar-sesion", function(req, res){
    const datos = req.body;
    const dni = datos.dni;
    const password = datos.password;
    const buscar = "SELECT * FROM tabla_usuarios WHERE dni = ?";
    conexion.query(buscar, [dni], function(error, rows) {
        if (error) {
            res.status(500).send("Error interno al buscar usuario");
            return;
        }
        if (rows.length === 0) {
            res.send("Usuario no encontrado");
        } else {
            const usuario = rows[0];
            bcrypt.compare(password, usuario.password, function(err, result) {
                if (err) {
                    res.status(500).send("Error interno al comparar contraseñas");
                    return;
                }
                if (result) {
                    res.render(path.join(__dirname, 'html', 'mp.html'), {total: req.session.total});
                } else {
                    res.send("DNI y/o Contraseña incorrecta");
                }
            });
        }
    });
});

const PORT = 3001; // Cambiar el puerto a 3001
app.listen(PORT, () => console.log(`Servidor corriendo en puerto ${PORT}`));
