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
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
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
    // ¡ELIMINAR BASEURL si ya tienes credenciales TEST-!
    // baseUrl: "https://api.mercadopago.com/checkout/preferences", // <--- ¡ESTA LÍNEA SE ELIMINA!
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
    const gameId = req.params.gameId;
    const userId = req.user.id; // Obtenemos el ID del usuario del token JWT
    const username = req.user.username; // Obtenemos el username del token para Mercado Pago
    const userEmail = req.user.email; // Obtenemos el email del token para Mercado Pago

    // Obtiene la hora actual en la zona horaria de Argentina
    const now = DateTime.now().setZone("America/Argentina/Buenos_Aires");

    try { // <-- Inicio del try principal de la ruta
        // 1. Obtener los detalles de la partida
        const gameResult = await pool.query('SELECT * FROM games WHERE id = $1', [gameId]);
        const game = gameResult.rows[0];

        if (!game) {
            return res.status(404).json({ message: 'Partida no encontrada.' });
        }

        // 2. Verificar si el registro está abierto y si no está llena
        // Convierte las fechas de la BD a objetos Luxon para comparar en la misma zona horaria
        const regOpen = DateTime.fromJSDate(game.registration_open_at).setZone("America/Argentina/Buenos_Aires");
        const regClose = DateTime.fromJSDate(game.registration_close_at).setZone("America/Argentina/Buenos_Aires");
        const scheduled = DateTime.fromJSDate(game.scheduled_time).setZone("America/Argentina/Buenos_Aires");

        // --- NUEVOS CONSOLE.LOG DE DEPURACIÓN EN LA RUTA ---
        console.log(`\n--- DEBUG REGISTRO EN PARTIDA ${gameId} ---`);
        console.log(`Hora actual (now):      ${now.toISO()} (Local: ${now.toLocaleString(DateTime.DATETIME_FULL)})`);
        console.log(`Reg Open (BD):          ${regOpen.toISO()} (Local: ${regOpen.toLocaleString(DateTime.DATETIME_FULL)})`);
        console.log(`Reg Close (BD):         ${regClose.toISO()} (Local: ${regClose.toLocaleString(DateTime.DATETIME_FULL)})`);
        console.log(`Partida Inicia (scheduled): ${scheduled.toISO()} (Local: ${scheduled.toLocaleString(DateTime.DATETIME_FULL)})`);
        console.log(`Tipo de now: ${typeof now}, Tipo de regOpen: ${typeof regOpen}`);
        console.log(`Valores Unix (ms): now=<span class="math-inline">\{now\.toMillis\(\)\}, regOpen\=</span>{regOpen.toMillis()}`);
        console.log(`now < regOpen ? ${now < regOpen}`); // ¿Aún no abrió?
        console.log(`now > regClose ? ${now > regClose}`); // ¿Ya cerró?
        console.log(`now > scheduled ? ${now > scheduled}`); // ¿Ya empezó la partida?
        console.log(`-------------------------------------------`);
        // --- FIN NUEVOS CONSOLE.LOG ---


        // Validación de estado de la partida
        if (game.status !== 'SCHEDULED' && game.status !== 'REGISTRATION_OPEN') {
            return res.status(400).json({ message: 'El registro para esta partida no está abierto (estado inválido).' });
        }

        // Validaciones de tiempo de registro
        if (now < regOpen) { // Si la hora actual es anterior a la hora de apertura
            return res.status(400).json({ message: 'El registro para esta partida aún no ha abierto.' });
        }
        if (now > regClose) { // Si la hora actual es posterior a la hora de cierre
            return res.status(400).json({ message: 'El registro para esta partida ya ha cerrado.' });
        }
        // También podemos verificar que la partida no haya comenzado
        if (now > scheduled) {
            return res.status(400).json({ message: 'La partida ya ha comenzado o terminado.' });
        }

        // Validación de cupo de jugadores
        if (game.current_players >= game.max_players) {
            return res.status(400).json({ message: 'La partida está llena. Intenta otra.' });
        }

        // 3. Verificar si el usuario ya está registrado en esta partida
        const existingRegistration = await pool.query(
            'SELECT * FROM game_participants WHERE game_id = $1 AND user_id = $2',
            [gameId, userId]
        );
        if (existingRegistration.rows.length > 0) {
            return res.status(409).json({ message: 'Ya estás registrado en esta partida.' });
        }

        // --- Generar los 5 cartones de bingo para el jugador ---
        const userBingoCards = [];
        for (let i = 0; i < 5; i++) {
            userBingoCards.push(generateBingoCard());
        }
        const cardsJson = JSON.stringify(userBingoCards);

        // --- Lógica de Integración con Mercado Pago ---
        const preference = {
            items: [
                {
                    title: `Inscripción a partida de Bingo #${gameId} - ${scheduled.toLocaleString(DateTime.DATETIME_FULL)}`,
                    unit_price: parseFloat(game.entry_fee),
                    quantity: 1,
                    currency_id: "ARS",
                }
            ],
            payer: {
    // ¡IMPORTANTE! Usa el email completo de tu COMPRADOR DE PRUEBA de Mercado Pago aquí
    email: 'TESTUSER1180747306@testuser.com', // CORRECCIÓN: Agrega "@testuser.com"
},
            external_reference: `<span class="math-inline">\{gameId\}\-</span>{userId}`, // CORRECCIÓN: Usar template literal directamente
           back_urls: {
           success: `${process.env.NGROK_URL}/api/payments/success`, // <-- ¡AQUÍ ESTÁ LA CORRECCIÓN!
           failure: `${process.env.NGROK_URL}/api/payments/failure`,
           pending: `${process.env.NGROK_URL}/api/payments/pending`,
           },
            auto_return: "approved", // Redirige automáticamente al usuario si el pago es aprobado
            // ¡IMPORTANTE! Esta URL DEBE SER PÚBLICA. Usa ngrok para pruebas locales.
            notification_url: `${process.env.NGROK_URL}/api/payments/webhook?source_news=webhooks`,
        };

        let mpResponse;
        try { // <-- Inicio del try para la llamada a Mercado Pago
            const preferenceInstance = new mercadopago.Preference(client); // CORRECTO: Usa mercadopago.Preference
            mpResponse = await preferenceInstance.create({ body: preference });

            // --- NUEVO CONSOLE.LOG PARA LA RESPUESTA DE MP ---
            console.log(`\n--- DEBUG RESPUESTA MERCADO PAGO ---`);
            console.log(`Status Code MP: ${mpResponse.statusCode}`); // Código HTTP de la respuesta de MP
            console.log(`MP Response Body:`, JSON.stringify(mpResponse.body, null, 2)); // Contenido del body de MP
            console.log(`MP Response Headers:`, JSON.stringify(mpResponse.headers, null, 2)); // Headers de la respuesta de MP
            console.log(`------------------------------------\n`);
            // --- FIN NUEVO CONSOLE.LOG ---

            // Si mpResponse.body es null o undefined, esto aún fallará.
            // Pero el log anterior nos mostrará lo que MP realmente envió.
            const checkoutUrl = mpResponse.body ? mpResponse.body.init_point : null; // Acceso seguro
            const preferenceId = mpResponse.body ? mpResponse.body.id : null; // Acceso seguro


            // 4. Registrar al usuario en la partida con estado PENDING y los cartones
            await pool.query(
                `INSERT INTO game_participants (game_id, user_id, registration_time, payment_status, mp_preference_id, card_numbers)
                 VALUES ($1, $2, $3, $4, $5, $6)`,
                [gameId, userId, now.toJSDate(), 'PENDING', preferenceId, cardsJson]
            );

            res.status(200).json({
                message: 'Redirige al usuario para completar el pago.',
                checkoutUrl: checkoutUrl,
                preferenceId: preferenceId
            });

        } catch (mpError) { // <-- Captura de errores de Mercado Pago
            console.error('Error directo del SDK de Mercado Pago:', mpError);
            // Si el error viene con una respuesta HTTP, puedes intentar acceder a ella
            if (mpError.status_code) {
                 console.error(`MP Error Status Code: ${mpError.status_code}`);
            }
            if (mpError.message && typeof mpError.message === 'object') {
                 console.error(`MP Error Message Body:`, JSON.stringify(mpError.message, null, 2));
            } else {
                 console.error(`MP Error Message: ${mpError.message}`);
            }
            res.status(500).json({ message: 'Error interno del servidor al procesar el pago.', details: mpError.message || 'Error desconocido del SDK de MP.' });
        } // <-- Cierre del catch de Mercado Pago

    } catch (error) { // <-- Captura de errores generales de la ruta
        console.error('Error general en la ruta de registro:', error);
        res.status(500).json({ message: 'Error interno del servidor durante el registro de partida.', details: error.message });
    }
});


// --- Lógica de Socket.IO (Comunicación en tiempo real) ---
io.on('connection', (socket) => {
    console.log(`Usuario conectado: ${socket.id}`);

    // Manejar eventos de chat
    socket.on('chatMessage', (msg) => {
        console.log(`Mensaje de chat recibido de ${socket.id}: ${msg}`);
        io.emit('chatMessage', { user: socket.id, message: msg });
    });

    // Manejar un evento de unión a un juego (cuando el usuario entra a una partida)
    socket.on('joinGame', (gameId) => {
        socket.join(gameId); // Unir al usuario a una "sala" de juego específica
        console.log(`Usuario ${socket.id} se unió al juego ${gameId}`);
        socket.emit('gameStatus', { message: `Bienvenido al juego ${gameId}!` });
    });

    // Cuando un usuario se desconecta
    socket.on('disconnect', () => {
        console.log(`Usuario desconectado: ${socket.id}`);
    });
});


// --- Rutas de Retorno de Mercado Pago (para el navegador del usuario) ---
// ... (success, failure, pending)

// --- Ruta del Webhook (Notificaciones IPN de Mercado Pago) ---
// --- Ruta del Webhook (Notificaciones IPN de Mercado Pago) ---
app.post('/api/payments/webhook', async (req, res) => { // <-- Asegúrate de que sea 'async'
    console.log("Webhook de Mercado Pago recibido:", req.query);
    console.log("Cuerpo del Webhook:", req.body);

    const topic = req.query.topic || req.query.type; // 'topic' o 'type' para saber el tipo de notificación
    const paymentId = req.body.data ? req.body.data.id : null; // El ID del pago

    if (!paymentId || topic !== 'payment') {
        console.log("Webhook no es de pago o ID de pago faltante. Ignorando.");
        return res.status(200).send('OK'); // Siempre responder 200 OK
    }

    try {
        // 1. Obtener detalles del pago de Mercado Pago usando el ID del pago
        // Necesitas el Access Token para esta llamada
        const mpPaymentResponse = await mercadopago.payment.findById(paymentId);
        const payment = mpPaymentResponse.body;

        console.log("Detalles del Pago obtenidos de MP:", JSON.stringify(payment, null, 2));

        // Extraer external_reference para encontrar tu registro
        const externalReference = payment.external_reference;
        if (!externalReference) {
            console.warn("Referencia externa faltante en el pago:", paymentId);
            return res.status(200).send('OK');
        }

        const [gameId, userId] = externalReference.split('-');

        if (!gameId || !userId) {
            console.warn("Formato de referencia externa inválido:", externalReference);
            return res.status(200).send('OK');
        }

        // 2. Procesar el estado del pago
        if (payment.status === 'approved') {
            // El pago fue aprobado
            console.log(`Pago ${paymentId} APROBADO para gameId: ${gameId}, userId: ${userId}`);

            // 2.1. Actualizar el estado del participante en la base de datos a 'COMPLETED'
            await pool.query(
                `UPDATE game_participants SET payment_status = 'COMPLETED', is_winner = FALSE
                 WHERE game_id = $1 AND user_id = $2 AND payment_status = 'PENDING'`,
                [gameId, userId]
            );

            // 2.2. Incrementar el contador de jugadores en la tabla 'games'
            await pool.query(
                `UPDATE games SET current_players = current_players + 1
                 WHERE id = $1`,
                [gameId]
            );
            console.log(`Participante ${userId} en juego ${gameId} actualizado a COMPLETED y contador de jugadores incrementado.`);

            // Opcional: Notificar a los usuarios en tiempo real via Socket.IO
            io.to(gameId).emit('playerJoined', { userId, gameId, status: 'approved' });

        } else if (payment.status === 'rejected') {
            // El pago fue rechazado
            console.log(`Pago ${paymentId} RECHAZADO para gameId: ${gameId}, userId: ${userId}`);
            await pool.query(
                `UPDATE game_participants SET payment_status = 'REJECTED'
                 WHERE game_id = $1 AND user_id = $2 AND payment_status = 'PENDING'`,
                [gameId, userId]
            );
            console.log(`Participante ${userId} en juego ${gameId} actualizado a REJECTED.`);

        } else if (payment.status === 'pending') {
            // El pago está pendiente (no es necesario hacer nada extra si ya está en PENDING en DB)
            console.log(`Pago ${paymentId} PENDIENTE para gameId: ${gameId}, userId: ${userId}`);
        }

        res.status(200).send('Webhook procesado exitosamente');

    } catch (error) {
        console.error('Error al procesar el webhook de Mercado Pago:', error);
        res.status(500).send('Error interno del servidor al procesar el webhook'); // En caso de error, responder 500
    }
});
// --- Programación de Tareas Diarias (Node-Cron) ---

// Tarea para crear las partidas de hoy y mañana al iniciar el servidor
async function setupInitialGames() {
    const today = DateTime.now().setZone("America/Argentina/Buenos_Aires"); // Usa Luxon para la fecha actual en la zona horaria
    await createDailyGames(today.toJSDate()); // Pasa un objeto Date nativo si la función lo espera, o directamente DateTime

    const tomorrow = today.plus({ days: 1 }); // Suma un día con Luxon
    await createDailyGames(tomorrow.toJSDate()); // Pasa un objeto Date nativo
}

// Ejecutar al iniciar el servidor
setupInitialGames();

// Programa la tarea para que se ejecute todos los días a la 00:01 (justo después de medianoche)
cron.schedule('1 0 * * *', async () => {
    console.log('Ejecutando tarea cron: Creando partidas para el nuevo día.');
    const today = DateTime.now().setZone("America/Argentina/Buenos_Aires");
    await createDailyGames(today.toJSDate());
}, {
    timezone: "America/Argentina/Buenos_Aires" // ¡MANTENER LA ZONA HORARIA AQUÍ!
});


// --- Iniciar el servidor ---
server.listen(PORT, () => {
    console.log(`Servidor de Bingo escuchando en el puerto ${PORT}`);
    console.log(`Accede a http://localhost:${PORT} en tu navegador.`);
});