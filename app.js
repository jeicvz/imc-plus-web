const express = require('express');
const sql = require('mssql');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const path = require('path');
const multer = require('multer'); 
const fs = require('fs'); 
const { OAuth2Client } = require('google-auth-library');

const app = express();
const client = new OAuth2Client('996749304935-mav75khojhn4ibjasoglbj0iilmko4o6.apps.googleusercontent.com');

// --- CAMBIO PARA EL SERVIDOR ---
// Usa las credenciales de Railway si existen, si no, usa las de tu PC (localhost)
const config = {
    user: process.env.DB_USER || 'sa', 
    password: process.env.DB_PASSWORD || '123456', 
    server: process.env.DB_SERVER || 'localhost', 
    database: process.env.DB_NAME || 'imc_plus', 
    options: {
        encrypt: false, 
        trustServerCertificate: true
    },
    port: parseInt(process.env.DB_PORT) || 1433 
};

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
    secret: process.env.SESSION_SECRET || 'secreto_imc_full_2026', // Mejor práctica
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

        let pool = await sql.connect(config);
        let result = await pool.request()
            .input('email', sql.NVarChar, email)
            .query('SELECT * FROM Usuarios WHERE email = @email');

        let user;
        if (result.recordset.length === 0) {
            await pool.request()
                .input('nombre', sql.NVarChar, nombre)
                .input('email', sql.NVarChar, email)
                .input('foto', sql.NVarChar, fotoGoogle)
                .input('username', sql.NVarChar, email.split('@')[0]) 
                .query("INSERT INTO Usuarios (nombre, username, email, password, foto_perfil) VALUES (@nombre, @username, @email, 'GOOGLE_AUTH', @foto)");
            
            let resNuevo = await pool.request().input('email', sql.NVarChar, email).query('SELECT * FROM Usuarios WHERE email = @email');
            user = resNuevo.recordset[0];
        } else {
            user = result.recordset[0];
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
        let pool = await sql.connect(config);
        const checkUser = await pool.request()
            .input('email', sql.NVarChar, email)
            .query('SELECT id FROM Usuarios WHERE email = @email');

        if (checkUser.recordset.length > 0) {
            return res.status(400).json({ 
                success: false, 
                code: 'EMAIL_EXISTS', 
                message: 'Este correo ya está registrado.' 
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.request()
            .input('nombre', sql.NVarChar, nombre)
            .input('username', sql.NVarChar, username || email.split('@')[0]) 
            .input('email', sql.NVarChar, email)
            .input('password', sql.NVarChar, hashedPassword)
            .query('INSERT INTO Usuarios (nombre, username, email, password) VALUES (@nombre, @username, @email, @password)');
        
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
        let pool = await sql.connect(config);
        let result = await pool.request().input('email', sql.NVarChar, email).query('SELECT * FROM Usuarios WHERE email = @email');
        
        if (result.recordset.length > 0) {
            const user = result.recordset[0];
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
        let pool = await sql.connect(config);
        let result = await pool.request()
            .input('email', sql.NVarChar, email)
            .query('SELECT * FROM Usuarios WHERE email = @email');
        
        if (result.recordset.length === 0) {
            return res.render('recuperar', { error: "Este correo no está registrado en el sistema.", success: null });
        }

        const user = result.recordset[0];
        
        if (user.password === 'GOOGLE_AUTH') {
            return res.render('recuperar', { error: "Este correo usa inicio de sesión con Google. No necesitas contraseña.", success: null });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        await pool.request()
            .input('email', sql.NVarChar, email)
            .input('password', sql.NVarChar, hashedPassword)
            .query('UPDATE Usuarios SET password = @password WHERE email = @email');

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
        let pool = await sql.connect(config);
        
        let resultEstado = await pool.request()
            .input('imc', sql.Decimal(5, 2), imc)
            .query('SELECT dbo.fn_CalcularEstadoIMC(@imc) as estado');
        
        const estadoCientifico = resultEstado.recordset[0].estado;

        if (req.session.usuarioId) {
            await pool.request()
                .input('IdUsuario', sql.Int, req.session.usuarioId)
                .input('NombreUsuario', sql.NVarChar, req.session.nombre)
                .input('Peso', sql.Decimal(5, 2), peso)
                .input('Altura', sql.Decimal(5, 2), altura)
                .input('ResultadoIMC', sql.Decimal(5, 2), imc)
                .input('Estado', sql.NVarChar, estadoCientifico)
                .execute('sp_GuardarHistorial'); 
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
        let pool = await sql.connect(config);
        let result = await pool.request()
            .input('uid', sql.Int, req.session.usuarioId)
            .query('SELECT * FROM Historial WHERE id_del_usuario = @uid ORDER BY fecha DESC');
        res.render('historial', { 
            registros: result.recordset, 
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
        let pool = await sql.connect(config);
        await pool.request()
            .input('uid', sql.Int, req.session.usuarioId)
            .query('DELETE FROM Historial WHERE id_del_usuario = @uid');
        
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
        let pool = await sql.connect(config);
        let result = await pool.request()
            .input('id', sql.Int, req.session.usuarioId)
            .query('SELECT nombre, email, username, foto_perfil FROM Usuarios WHERE id = @id');

        if (result.recordset.length > 0) {
            res.render('editar-perfil', { 
                nombre: req.session.nombre || null, 
                usuario: req.session.username || null,
                foto: req.session.foto,
                datos: result.recordset[0],
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
        let pool = await sql.connect(config);
        
        req.session.username = username; 

        if (fotoPath) {
            await pool.request()
                .input('id', sql.Int, req.session.usuarioId)
                .input('username', sql.NVarChar, username)
                .input('foto', sql.NVarChar, fotoPath)
                .query('UPDATE Usuarios SET username = @username, foto_perfil = @foto WHERE id = @id');
            req.session.foto = fotoPath; 
        } else {
            await pool.request()
                .input('id', sql.Int, req.session.usuarioId)
                .input('username', sql.NVarChar, username)
                .query('UPDATE Usuarios SET username = @username WHERE id = @id');
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
        let pool = await sql.connect(config);
        const result = await pool.request()
            .input('id', sql.Int, req.session.usuarioId)
            .query('SELECT foto_perfil FROM Usuarios WHERE id = @id');

        const currentPhoto = result.recordset[0]?.foto_perfil;

        if (currentPhoto && currentPhoto.includes('/uploads/')) {
            const fullPath = path.join(__dirname, 'public', currentPhoto);
            if (fs.existsSync(fullPath)) {
                fs.unlinkSync(fullPath); 
            }
        }

        await pool.request()
            .input('id', sql.Int, req.session.usuarioId)
            .query('UPDATE Usuarios SET foto_perfil = NULL WHERE id = @id');

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

// --- CAMBIO PARA EL SERVIDOR: PUERTO DINÁMICO ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor en http://localhost:${PORT}`));