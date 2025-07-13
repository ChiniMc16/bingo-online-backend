// index.js (Tu servidor Node.js para el Bingo Online)

require('dotenv').config(); // Carga las variables de entorno desde .env

const express = require('express');
const http = require('http'); // Módulo http de Node.js para crear el servidor
const { Server } = require('socket.io'); // Importa la clase Server de socket.io
const cors = require('cors'); // Para permitir conexiones desde el cliente Android
const { Pool } = require('pg'); // Cliente de PostgreSQL para Node.js
const bcrypt = require('bcryptjs'); // Para el hashing seguro de contraseñas
const jwt = require('jsonwebtoken'); // Para generar y verificar tokens JWT
const cron = require('node-cron'); // Para programar tareas diarias
const mercadopago = require('mercadopago'); // SDK de Mercado Pago
const { DateTime } = require('luxon'); // Para manejo avanzado de fechas y zonas horarias

const app = express();
const server = http.createServer(app); // Crea el servidor HTTP usando Express
const io = new Server(server, {
    cors: {
        origin: "*", // Permite conexiones desde cualquier origen (para desarrollo). ¡CAMBIAR EN PRODUCCIÓN!
        methods: ["GET", "POST"]
    }
});



const PORT = process.env.PORT || 3000; // Puerto del servidor, usa el de las variables de entorno o 3000 por defecto

// Configuración de la base de datos usando variables de entorno
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// --- Constantes del juego ---
const GAME_TIMES = ['20:00', '22:00']; // Horas de las partidas (ej. 20:00 o 22:00 local)
const MAX_PLAYERS_PER_GAME = 100;
const ENTRY_FEE = 10.00; // Costo de entrada a cada partida
// --- Fin Constantes del juego ---

// --- Configuración de Mercado Pago ---
// Crea una instancia del cliente de Mercado Pago con tu Access Token
const client = new mercadopago.MercadoPagoConfig({
    accessToken: process.env.MP_ACCESS_TOKEN, // ¡Asegúrate de que este token sea correcto y activo en MP!
    options: {
        timeout: 15000, // Timeout para las peticiones (15 segundos)
    },
    debug: true, // Habilita el modo debug del SDK para ver más información en consola
});
// --- Fin Configuración de Mercado Pago ---


// --- Middleware ---
app.use(cors()); // Habilita CORS
app.use(express.json()); // Habilita el parsing de JSON en las peticiones


// Middleware para verificar JWT (para rutas protegidas)
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Esperamos el formato 'Bearer TOKEN'

    if (token == null) {
        console.log("No token provided or malformed Authorization header.");
        return res.sendStatus(401); // Si no hay token, no autorizado
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            console.error("Error al verificar token JWT:", err.message);
            return res.sendStatus(403); // Token inválido o expirado
        }
        req.user = user; // Guarda la información del usuario decodificada en la petición
        next(); // Continúa con la siguiente función de middleware/ruta
    });
};

// --- Funciones de Lógica de Juego ---

// Función para generar un cartón de bingo (75 bolas)
function generateBingoCard() {
    const card = [];
    const columns = {
        'B': [], // 1-15
        'I': [], // 16-30
        'N': [], // 31-45
        'G': [], // 46-60
        'O': []  // 61-75
    };

    // Rellenar cada columna con 5 números únicos
    function fillColumn(start, end, count) {
        const numbers = Array.from({ length: end - start + 1 }, (_, i) => start + i); // Array de números posibles
        const selected = [];
        for (let i = 0; i < count; i++) {
            const randomIndex = Math.floor(Math.random() * numbers.length);
            selected.push(numbers.splice(randomIndex, 1)[0]); // Saca el número y lo añade
        }
        return selected.sort((a, b) => a - b); // Ordenar para que sea más fácil de leer
    }

    columns['B'] = fillColumn(1, 15, 5);
    columns['I'] = fillColumn(16, 30, 5);
    columns['N'] = fillColumn(31, 45, 5); // La casilla central se maneja después
    columns['G'] = fillColumn(46, 60, 5);
    columns['O'] = fillColumn(61, 75, 5);

    // La columna 'N' tiene una casilla "GRATIS" (índice 2, el del medio)
    columns['N'][2] = 0; // Usaremos 0 para representar la casilla gratis

    // Reorganizar en un formato de $5 \times 5$ (para facilidad de almacenamiento/visualización)
    for (let row = 0; row < 5; row++) {
        card.push([
            columns['B'][row],
            columns['I'][row],
            columns['N'][row],
            columns['G'][row],
            columns['O'][row]
        ]);
    }

    return card; // Retorna un array de arrays representando el cartón
}

// Función para crear las partidas diarias
async function createDailyGames(dateInput) { // Recibe 'dateInput' como un objeto Date o String
    // Convertir la fecha de entrada a un objeto DateTime en la zona horaria local
    const date = DateTime.fromJSDate(dateInput).setZone("America/Argentina/Buenos_Aires");

    console.log(`Intentando crear partidas para el día: ${date.toLocaleString(DateTime.DATE_FULL)}`);
    for (const timeStr of GAME_TIMES) {
        const [hours, minutes] = timeStr.split(':').map(Number);

        // 1. Definir la hora programada de la partida (ej. 20:00 o 22:00 del día 'date')
        let scheduledTime = date.set({ hour: hours, minute: minutes, second: 0, millisecond: 0 });

        // 2. Definir la hora de apertura del registro (00:00 del día de la partida)
        let registrationOpenTime = scheduledTime.startOf('day'); // Usa startOf('day') de Luxon

        // 3. Definir la hora de cierre del registro (exactamente al inicio de la partida)
        let registrationCloseTime = scheduledTime; // Cierra al inicio de la partida


        // --- Debugging ---
        console.log(`Debug - Partida ${timeStr} en ${scheduledTime.toLocaleString(DateTime.DATE_FULL)}`);
        console.log(`Debug - scheduledTime: ${scheduledTime.toISO()} (Local: ${scheduledTime.toLocaleString(DateTime.DATETIME_FULL)})`);
        console.log(`Debug - Apertura registro: ${registrationOpenTime.toISO()} (Local: ${registrationOpenTime.toLocaleString(DateTime.DATETIME_FULL)})`);
        console.log(`Debug - Cierre registro: ${registrationCloseTime.toISO()} (Local: ${registrationCloseTime.toLocaleString(DateTime.DATETIME_FULL)})`);
        // --- Fin Debugging ---


        // Evitar crear partidas duplicadas (la comparación de fechas funciona mejor con ISO)
        const existingGame = await pool.query(
            'SELECT id FROM games WHERE scheduled_time = $1',
            [scheduledTime.toJSDate()] // Convertir a Date para la DB si es necesario
        );

        if (existingGame.rows.length === 0) {
            try {
                await pool.query(
                    `INSERT INTO games (scheduled_time, registration_open_at, registration_close_at, max_players, entry_fee, status)
                     VALUES ($1, $2, $3, $4, $5, $6)`,
                    [
                        scheduledTime.toJSDate(), // Convertir a Date para la DB
                        registrationOpenTime.toJSDate(), // Convertir a Date para la DB
                        registrationCloseTime.toJSDate(), // Convertir a Date para la DB
                        MAX_PLAYERS_PER_GAME, ENTRY_FEE, 'SCHEDULED'
                    ]
                );
                console.log(`Partida creada: ${timeStr} para ${scheduledTime.toLocaleString(DateTime.DATE_FULL)}`);
            } catch (err) {
                console.error(`Error creando partida para ${timeStr}:`, err.message);
            }
        } else {
            console.log(`La partida para ${timeStr} en ${scheduledTime.toLocaleString(DateTime.DATE_FULL)} ya existe.`);
        }
    }
}

// --- Rutas de Prueba (REST API) ---
app.get('/', (req, res) => {
    res.send('Servidor de Bingo Online funcionando!');
});

app.get('/api/saludo', (req, res) => {
    res.json({ message: '¡Hola desde la API REST del servidor de Bingo!' });
});

// Ruta de prueba para la conexión a la base de datos
app.get('/api/db-test', async (req, res) => {
    try {
        const client = await pool.connect(); // Intenta conectar a la DB
        const result = await client.query('SELECT NOW()'); // Ejecuta una consulta simple
        client.release(); // Libera la conexión
        res.json({
            message: 'Conexión a la base de datos exitosa!',
            currentTime: result.rows[0].now
        });
    } catch (err) {
        console.error('Error al conectar o consultar la base de datos:', err);
        res.status(500).json({
            message: 'Error al conectar a la base de datos.',
            error: err.message
        });
    }
});

// --- Rutas de Autenticación de Usuarios ---

// Ruta de Registro de Usuario
app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({ message: 'Todos los campos son obligatorios.' });
    }

    try {
        // 1. Verificar si el usuario o email ya existen
        const existingUser = await pool.query('SELECT id FROM users WHERE username = $1 OR email = $2', [username, email]);
        if (existingUser.rows.length > 0) {
            return res.status(409).json({ message: 'El nombre de usuario o el correo electrónico ya están registrados.' });
        }

        // 2. Hash de la contraseña
        const salt = await bcrypt.genSalt(10); // Genera un "salt" para la seguridad del hash
        const passwordHash = await bcrypt.hash(password, salt);

        // 3. Insertar nuevo usuario en la base de datos
        const result = await pool.query(
            'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username, email',
            [username, email, passwordHash]
        );

        const newUser = result.rows[0];
        res.status(201).json({ message: 'Usuario registrado exitosamente!', user: { id: newUser.id, username: newUser.username, email: newUser.email } });

    } catch (error) {
        console.error('Error en el registro:', error);
        res.status(500).json({ message: 'Error interno del servidor durante el registro.', details: error.message });
    }
});

// Ruta de Login de Usuario
app.post('/api/login', async (req, res) => {
    const { identifier, password } = req.body; // 'identifier' puede ser username o email

    if (!identifier || !password) {
        return res.status(400).json({ message: 'Nombre de usuario/email y contraseña son obligatorios.' });
    }

    try {
        // 1. Buscar usuario por username o email
        const userResult = await pool.query('SELECT * FROM users WHERE username = $1 OR email = $1', [identifier]);
        const user = userResult.rows[0];

        if (!user) {
            return res.status(401).json({ message: 'Credenciales inválidas.' });
        }

        // 2. Comparar la contraseña ingresada con el hash almacenado
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            return res.status(401).json({ message: 'Credenciales inválidas.' });
        }

        // 3. Generar un token JWT
        // El payload del token contendrá información para identificar al usuario en futuras peticiones
        const token = jwt.sign(
            { id: user.id, username: user.username, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: '1h' } // El token expira en 1 hora
        );

        res.json({ message: 'Inicio de sesión exitoso!', token: token, user: { id: user.id, username: user.username, email: user.email, balance: user.balance } });

    } catch (error) {
        console.error('Error en el login:', error);
        res.status(500).json({ message: 'Error interno del servidor durante el login.', details: error.message });
    }
});

// Ejemplo de ruta protegida (solo accesible con un token JWT válido)
app.get('/api/protected', authenticateToken, (req, res) => {
    res.json({ message: `Bienvenido, ${req.user.username}! Esta es una ruta protegida. Su ID es ${req.user.id}.` });
});


// --- Rutas de Gestión de Partidas ---

// Ruta para obtener la lista de partidas disponibles
app.get('/api/games', authenticateToken, async (req, res) => {
    try {
        // Se pueden filtrar por estado, hora, etc. Por ahora, todas las futuras o registrables.
        const now = DateTime.now().setZone("America/Argentina/Buenos_Aires"); // Usa Luxon para la hora actual
        const games = await pool.query(
            `SELECT id, scheduled_time, registration_open_at, registration_close_at,
                    max_players, current_players, entry_fee, status
             FROM games
             WHERE scheduled_time >= $1
             ORDER BY scheduled_time ASC`,
            [now.toJSDate()] // Pasa la fecha como objeto Date nativo a la base de datos
        );
        res.json(games.rows);
    } catch (error) {
        console.error('Error al obtener partidas:', error);
        res.status(500).json({ message: 'Error interno del servidor al obtener partidas.', details: error.message });
    }
});

// Ruta para que un usuario se registre en una partida
app.post('/api/games/:gameId/register', authenticateToken, async (req, res) => {
    const { gameId } = req.params;
    const { id: userId, email: userEmail } = req.user;
    const clientDB = await pool.connect();

    try {
        await clientDB.query('BEGIN');

        const gameResult = await clientDB.query('SELECT * FROM games WHERE id = $1 FOR UPDATE', [gameId]);
        const game = gameResult.rows[0];

        if (!game) throw new Error('Partida no encontrada.');
        if (game.status !== 'SCHEDULED') throw new Error('El registro para esta partida no está abierto.');
        const now = DateTime.now().setZone("America/Argentina/Buenos_Aires");
        if (now > DateTime.fromJSDate(game.registration_close_at).setZone("America/Argentina/Buenos_Aires")) throw new Error('El registro para esta partida ya ha cerrado.');
        if (game.current_players >= game.max_players) throw new Error('La partida está llena.');
        
        const existingRegistration = await clientDB.query('SELECT * FROM game_participants WHERE game_id = $1 AND user_id = $2', [gameId, userId]);
        if (existingRegistration.rows.length > 0) throw new Error('Ya estás registrado en esta partida.');

         const preferenceBody = {
            items: [{
                title: `Inscripción a Bingo #${gameId}`,
                unit_price: parseFloat(game.entry_fee),
                quantity: 1,
                currency_id: "ARS",
            }],
            payer: {
                email: userEmail
            },
            external_reference: JSON.stringify({ gameId, userId }),
            back_urls: {
                success: `${process.env.RAILWAY_PUBLIC_URL}/api/payments/success`,
                failure: `${process.env.RAILWAY_PUBLIC_URL}/api/payments/failure`,
                pending: `${process.env.RAILWAY_PUBLIC_URL}/api/payments/pending`
            },
            auto_return: "approved",
            notification_url: `${process.env.RAILWAY_PUBLIC_URL}/api/payments/webhook`
        };
        
        const preference = new mercadopago.Preference(mpClient);
        const mpResponse = await preference.create({ body: preferenceBody });

        console.log("<-- Respuesta de Mercado Pago:", JSON.stringify(mpResponse, null, 2));

        const initPoint = mpResponse.sandbox_init_point || mpResponse.init_point;

        if (!initPoint) {
            throw new Error("Mercado Pago no devolvió una URL de pago válida.");
        }

        const preferenceId = mpResponse.id;
        const deepLinkUrl = initPoint.replace('https://', 'mercadopago://');

        console.log(`URL de pago generada: ${initPoint}`);
        console.log(`Deep Link generado: ${deepLinkUrl}`);
        console.log(`Preference ID: ${preferenceId}`);

        const userBingoCards = Array.from({ length: 5 }, () => generateBingoCard());
        await clientDB.query(
            `INSERT INTO game_participants (game_id, user_id, payment_status, mp_preference_id, card_numbers)
             VALUES ($1, $2, 'PENDING', $3, $4)`,
            [gameId, userId, preferenceId, JSON.stringify(userBingoCards)]
        );
        
        await clientDB.query('COMMIT');

        res.status(200).json({
            message: 'Preferencia creada.',
            checkoutUrl: initPoint,
            deepLinkUrl: deepLinkUrl
        });

    } catch (error) {
        await clientDB.query('ROLLBACK');
        console.error('Error en registro de partida:', error);
        res.status(500).json({ message: error.message || 'Error interno del servidor.' });
    } finally {
        clientDB.release();
    }
});


// Webhook de Mercado Pago
app.post('/api/payments/webhook', async (req, res) => {
    console.log("--- INICIO DE WEBHOOK RECIBIDO ---");
    console.log("==> QUERY PARAMS:", JSON.stringify(req.query, null, 2));
    console.log("==> BODY:", JSON.stringify(req.body, null, 2));
    console.log("--- FIN DE WEBHOOK RECIBIDO ---");
    
    // Aquí irá la lógica robusta que construyamos a partir de estos logs
    
    res.status(200).send('Webhook recibido y logueado.');
});


// --- Lógica de Socket.IO y Tareas Programadas ---
io.on('connection', (socket) => {
    // Este código solo se ejecuta si el middleware de autenticación fue exitoso
    console.log(`Usuario autenticado y conectado: ${socket.user.username} (ID: ${socket.id})`);

    socket.on('disconnect', () => {
        console.log(`Usuario desconectado: ${socket.user.username}`);
    });

    socket.on('joinGame', async (gameId) => {
        socket.join(String(gameId));
        console.log(`Usuario ${socket.user.username} se unió al juego ${gameId}`);
        socket.emit('gameStatus', { message: `¡Bienvenido al juego ${gameId}!` });

        try {
            const userId = socket.user.id; 
            const result = await pool.query(
                'SELECT card_numbers FROM game_participants WHERE game_id = $1 AND user_id = $2',
                [gameId, userId]
            );

            if (result.rows.length > 0) {
                const userCards = result.rows[0].card_numbers;
                socket.emit('yourCards', { cards: userCards });
                console.log(`Cartones enviados al usuario ${socket.user.username} para la partida ${gameId}`);
            } else {
                socket.emit('gameError', { message: 'No se encontraron tus cartones para esta partida.' });
            }
        } catch (error) {
            console.error('Error al obtener los cartones del usuario:', error);
            socket.emit('gameError', { message: 'Error al obtener tus cartones.' });
        }
    });
});

async function setupInitialGames() {
    const today = DateTime.now().setZone("America/Argentina/Buenos_Aires");
    await createDailyGames(today.toJSDate());
    const tomorrow = today.plus({ days: 1 });
    await createDailyGames(tomorrow.toJSDate());
}

setupInitialGames();

cron.schedule('1 0 * * *', () => {
    console.log('Ejecutando tarea cron para crear partidas del día siguiente.');
    const tomorrow = DateTime.now().setZone("America/Argentina/Buenos_Aires").plus({ days: 1 });
    createDailyGames(tomorrow.toJSDate());
}, {
    timezone: "America/Argentina/Buenos_Aires"
});

cron.schedule('* * * * *', async () => {
    console.log('Cron: Verificando partidas a iniciar...');
    const now = DateTime.now().setZone("America/Argentina/Buenos_Aires");

    try {
        const result = await pool.query(
            "SELECT id, scheduled_time FROM games WHERE status = 'SCHEDULED' AND scheduled_time <= $1",
            [now.toJSDate()]
        );

        for (const game of result.rows) {
            startGame(game.id); // ¡Inicia el juego!
        }
    } catch (error) {
        console.error('Cron: Error al verificar partidas a iniciar:', error);
    }
});


server.listen(PORT, () => console.log(`Servidor escuchando en puerto ${PORT}`));

(async () => {
    try {
        const result = await pool.query(`
            ALTER TABLE game_participants
            ADD COLUMN IF NOT EXISTS mp_payment_id VARCHAR(255);
        `);
        console.log("Columna 'mp_payment_id' añadida (si no existía).");
    } catch (err) {
        console.error("Error al añadir columna mp_payment_id:", err);
    }
})();