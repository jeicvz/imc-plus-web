const express = require('express');
const { Pool } = require('pg'); 
const bcrypt = require('bcryptjs');
const session = require('express-session');
const path = require('path');
const multer = require('multer'); 
const fs = require('fs'); 
const { OAuth2Client } = require('google-auth-library');

const app = express();
const client = new OAuth2Client('996749304935-mav75khojhn4ibjasoglbj0iilmko4o6.apps.googleusercontent.com');

// --- CAMBIO PARA EL SERVIDOR: Configuración de PostgreSQL ---
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

const uploadDir = path.join(__dirname, 'public/css/images/uploads/');
if (!fs.existsSync(uploadDir)){
    fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir); 
    },
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname);
        cb(null, `avatar-${req.session.usuarioId || Date.now()}${ext}`);
    }
});
const upload = multer({ storage: storage });

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: false }));
app.use(express.json()); 
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    secret: process.env.SESSION_SECRET || 'secreto_imc_full_2026', 
    resave: false,
    saveUninitialized: false
}));

// --- RUTAS DE NAVEGACIÓN ---
app.get('/login', (req, res) => {
    if (req.session.usuarioId) return res.redirect('/');
    res.render('login', { error: null }); 
});

app.get('/registro', (req, res) => {
    if (req.session.usuarioId) return res.redirect('/');
    res.render('registro', { error: null }); 
});

app.get('/recuperar', (req, res) => {
    if (req.session.usuarioId) return res.redirect('/');
    res.render('recuperar', { error: null, success: null }); 
});

app.get('/', (req, res) => {
    res.render('index', { 
        nombre: req.session.nombre || null, 
        usuario: req.session.username || null, 
        foto: req.session.foto || null, 
        resultado: null 
    });
});

app.get('/faq', (req, res) => {
    res.render('faq', { 
        nombre: req.session.nombre || null, 
        usuario: req.session.username || null,
        foto: req.session.foto || null 
    });
});

app.get('/piramide-salud', (req, res) => {
    res.render('piramide-salud', { 
        nombre: req.session.nombre || null, 
        usuario: req.session.username || null,
        foto: req.session.foto || null 
    });
});

app.get('/alimentos-recomendados', (req, res) => {
    res.render('alimentos-recomendados', { 
        nombre: req.session.nombre || null, 
        usuario: req.session.username || null,
        foto: req.session.foto || null 
    });
});

app.get('/datos-obesidad', (req, res) => {
    res.render('datos-obesidad', { 
        nombre: req.session.nombre || null, 
        usuario: req.session.username || null,
        foto: req.session.foto || null 
    });
});

app.get('/planbajopeso', (req, res) => {
    res.render('planbajopeso', { 
        nombre: req.session.nombre || null, 
        usuario: req.session.username || null,
        foto: req.session.foto || null 
    });
});

app.get('/planpesonormal', (req, res) => {
    res.render('planpesonormal', { 
        nombre: req.session.nombre || null, 
        usuario: req.session.username || null,
        foto: req.session.foto || null 
    });
});

app.get('/plansobrepeso', (req, res) => {
    res.render('plansobrepeso', { 
        nombre: req.session.nombre || null, 
        usuario: req.session.username || null,
        foto: req.session.foto || null 
    });
});

app.get('/planobesidad', (req, res) => {
    res.render('planobesidad', { 
        nombre: req.session.nombre || null, 
        usuario: req.session.username || null,
        foto: req.session.foto || null 
    });
});

// --- AUTENTICACIÓN GOOGLE ---
app.post('/auth-google', async (req, res) => {
    const { token } = req.body;
    try {
        const ticket = await client.verifyIdToken({
            idToken: token,
            audience: '996749304935-mav75khojhn4ibjasoglbj0iilmko4o6.apps.googleusercontent.com',
        });
        const payload = ticket.getPayload();
        const email = payload['email'];
        const nombre = payload['name'];
        const fotoGoogle = payload['picture'];

        let result = await pool.query('SELECT * FROM Usuarios WHERE email = $1', [email]);

        let user;
        if (result.rows.length === 0) {
            await pool.query(
                "INSERT INTO Usuarios (nombre, username, email, password, foto_perfil) VALUES ($1, $2, $3, 'GOOGLE_AUTH', $4)",
                [nombre, email.split('@')[0], email, fotoGoogle]
            );
            
            let resNuevo = await pool.query('SELECT * FROM Usuarios WHERE email = $1', [email]);
            user = resNuevo.rows[0];
        } else {
            user = result.rows[0];
        }

        req.session.usuarioId = user.id;
        req.session.nombre = user.nombre;
        req.session.username = user.username; 
        req.session.foto = user.foto_perfil;
        res.status(200).json({ status: "success" });
    } catch (err) {
        console.error(err);
        res.status(401).send("Error en la autenticación de Google");
    }
});

// --- REGISTRO ---
app.post('/registrar', async (req, res) => {
    const { nombre, email, password, username } = req.body; 
    try {
        const checkUser = await pool.query('SELECT id FROM Usuarios WHERE email = $1', [email]);

        if (checkUser.rows.length > 0) {
            return res.status(400).json({ 
                success: false, 
                code: 'EMAIL_EXISTS', 
                message: 'Este correo ya está registrado.' 
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query(
            'INSERT INTO Usuarios (nombre, username, email, password) VALUES ($1, $2, $3, $4)',
            [nombre, username || email.split('@')[0], email, hashedPassword]
        );
        
        res.status(200).json({ success: true, message: 'Usuario creado' });
    } catch (err) { 
        console.error(err);
        res.status(500).json({ success: false, message: 'Error interno del servidor' }); 
    }
});

// --- LOGIN TRADICIONAL ---
app.post('/auth', async (req, res) => {
    const { email, password } = req.body;
    try {
        let result = await pool.query('SELECT * FROM Usuarios WHERE email = $1', [email]);
        
        if (result.rows.length > 0) {
            const user = result.rows[0];
            if (user.password === 'GOOGLE_AUTH') return res.render('login', { error: "Usa el botón de Google." });
            
            const match = await bcrypt.compare(password, user.password);
            if (match) {
                req.session.usuarioId = user.id;
                req.session.nombre = user.nombre;
                req.session.username = user.username; 
                req.session.foto = user.foto_perfil;
                return res.redirect('/');
            }
        }
        res.render('login', { error: "Credenciales inválidas." });
    } catch (err) { 
        console.error(err);
        res.render('login', { error: "Error de servidor." }); 
    }
});

app.post('/recuperar', async (req, res) => {
    const { email, newPassword } = req.body;
    try {
        let result = await pool.query('SELECT * FROM Usuarios WHERE email = $1', [email]);
        
        if (result.rows.length === 0) {
            return res.render('recuperar', { error: "Este correo no está registrado en el sistema.", success: null });
        }

        const user = result.rows[0];
        
        if (user.password === 'GOOGLE_AUTH') {
            return res.render('recuperar', { error: "Este correo usa inicio de sesión con Google. No necesitas contraseña.", success: null });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        await pool.query('UPDATE Usuarios SET password = $1 WHERE email = $2', [hashedPassword, email]);

        res.render('recuperar', { error: null, success: "Contraseña actualizada con éxito. ¡Ya puedes iniciar sesión!" });

    } catch (err) { 
        console.error(err);
        res.render('recuperar', { error: "Ocurrió un error en el servidor. Intenta de nuevo.", success: null }); 
    }
});

// --- CÁLCULO IMC CORREGIDO ---
app.post('/calcular', async (req, res) => {
    const peso = parseFloat(req.body.peso);
    const altura = parseFloat(req.body.altura);

    if(isNaN(peso) || isNaN(altura) || altura === 0) {
        return res.status(400).json({ success: false, mensaje: "Datos inválidos" });
    }

    const imc = (peso / (altura * altura)).toFixed(2);

    try {
        let resultEstado = await pool.query('SELECT fn_CalcularEstadoIMC($1) as estado', [imc]);
        
        const estadoCientifico = resultEstado.rows[0].estado;

        if (req.session.usuarioId) {
            await pool.query(
                'CALL sp_GuardarHistorial($1, $2, $3, $4, $5, $6)',
                [req.session.usuarioId, req.session.nombre, peso, altura, imc, estadoCientifico]
            ); 
        }

        res.json({ 
            success: true,
            imc: parseFloat(imc),
            estado: estadoCientifico,
            mensaje: `Tu IMC es ${imc} (${estadoCientifico})`
        });

    } catch (err) { 
        console.error("DETALLE DEL ERROR EN CONSOLA:", err);
        res.status(500).json({ success: false, mensaje: "Error al guardar en la base de datos" }); 
    }
});

// --- HISTORIAL ---
app.get('/historial', async (req, res) => {
    if (!req.session.usuarioId) return res.redirect('/login');
    try {
        let result = await pool.query('SELECT * FROM Historial WHERE id_del_usuario = $1 ORDER BY fecha DESC', [req.session.usuarioId]);
        res.render('historial', { 
            registros: result.rows, 
            nombre: req.session.nombre || null, 
            usuario: req.session.username || null,
            foto: req.session.foto 
        });
    } catch (err) { 
        console.error(err);
        res.status(500).send("Error al cargar historial"); 
    }
});

app.get('/borrar-historial', async (req, res) => {
    if (!req.session.usuarioId) return res.redirect('/login');
    try {
        await pool.query('DELETE FROM Historial WHERE id_del_usuario = $1', [req.session.usuarioId]);
        res.redirect('/historial');
    } catch (err) {
        console.error("Error al borrar el historial:", err);
        res.status(500).send("No se pudo borrar el historial");
    }
});

// --- PERFIL ---
app.get('/editar-perfil', async (req, res) => {
    if (!req.session.usuarioId) return res.redirect('/login');
    try {
        let result = await pool.query('SELECT nombre, email, username, foto_perfil FROM Usuarios WHERE id = $1', [req.session.usuarioId]);

        if (result.rows.length > 0) {
            res.render('editar-perfil', { 
                nombre: req.session.nombre || null, 
                usuario: req.session.username || null,
                foto: req.session.foto,
                datos: result.rows[0],
                error: null,
                success: req.query.success 
            });
        } else {
            res.redirect('/');
        }
    } catch (err) {
        res.status(500).send("Error al obtener datos");
    }
});

app.post('/actualizar-perfil', upload.single('foto'), async (req, res) => {
    if (!req.session.usuarioId) return res.redirect('/login');

    const { username } = req.body;
    const fotoPath = req.file ? `/css/images/uploads/${req.file.filename}` : null;

    try {
        req.session.username = username; 

        if (fotoPath) {
            await pool.query(
                'UPDATE Usuarios SET username = $1, foto_perfil = $2 WHERE id = $3',
                [username, fotoPath, req.session.usuarioId]
            );
            req.session.foto = fotoPath; 
        } else {
            await pool.query(
                'UPDATE Usuarios SET username = $1 WHERE id = $2',
                [username, req.session.usuarioId]
            );
        }
        res.redirect('/editar-perfil?success=true');
    } catch (err) {
        console.error(err);
        res.status(500).send("Error al actualizar");
    }
});

// --- ELIMINAR FOTO ---
app.post('/eliminar-foto', async (req, res) => {
    if (!req.session.usuarioId) return res.redirect('/login');

    try {
        const result = await pool.query('SELECT foto_perfil FROM Usuarios WHERE id = $1', [req.session.usuarioId]);
        const currentPhoto = result.rows[0]?.foto_perfil;

        if (currentPhoto && currentPhoto.includes('/uploads/')) {
            const fullPath = path.join(__dirname, 'public', currentPhoto);
            if (fs.existsSync(fullPath)) {
                fs.unlinkSync(fullPath); 
            }
        }

        await pool.query('UPDATE Usuarios SET foto_perfil = NULL WHERE id = $1', [req.session.usuarioId]);

        req.session.foto = null;
        res.redirect('/editar-perfil?status=photo_deleted');
    } catch (err) {
        console.error("Error al eliminar foto:", err);
        res.status(500).send("Error interno al eliminar la foto");
    }
});

app.get('/logout', (req, res) => { 
    req.session.destroy(() => { res.redirect('/'); });
});
// --- RUTA SECRETA PARA CREAR TABLAS ---
app.get('/crear-tablas', async (req, res) => {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS Usuarios (
                id SERIAL PRIMARY KEY,
                nombre VARCHAR(100),
                username VARCHAR(50),
                email VARCHAR(100) UNIQUE,
                password VARCHAR(255),
                foto_perfil VARCHAR(255)
            );

            CREATE TABLE IF NOT EXISTS Historial (
                id SERIAL PRIMARY KEY,
                id_del_usuario INT,
                NombreUsuario VARCHAR(100),
                peso DECIMAL(5,2),
                altura DECIMAL(5,2),
                ResultadoIMC DECIMAL(5,2),
                Estado VARCHAR(50),
                fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE OR REPLACE FUNCTION fn_CalcularEstadoIMC(imc numeric)
            RETURNS varchar AS $$
            BEGIN
                IF imc < 18.5 THEN RETURN 'Bajo peso';
                ELSIF imc < 25.0 THEN RETURN 'Normal';
                ELSIF imc < 30.0 THEN RETURN 'Sobrepeso';
                ELSE RETURN 'Obesidad';
                END IF;
            END;
            $$ LANGUAGE plpgsql;

            CREATE OR REPLACE PROCEDURE sp_GuardarHistorial(
                p_id_usuario INT, p_nombre VARCHAR, p_peso NUMERIC, p_altura NUMERIC, p_imc NUMERIC, p_estado VARCHAR
            )
            LANGUAGE plpgsql AS $$
            BEGIN
                INSERT INTO Historial (id_del_usuario, NombreUsuario, peso, altura, ResultadoIMC, Estado)
                VALUES (p_id_usuario, p_nombre, p_peso, p_altura, p_imc, p_estado);
            END;
            $$;
        `);
        res.send("<h1 style='color:green;'>¡Misión Cumplida! Tablas creadas con éxito 🚀</h1><p>Ya puedes regresar a la página principal y registrarte.</p>");
    } catch (error) {
        res.send("<h1 style='color:red;'>Hubo un error:</h1><p>" + error.message + "</p>");
    }
});
// --- CAMBIO PARA EL SERVIDOR: PUERTO DINÁMICO ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor en http://localhost:${PORT}`));