require('dotenv').config(); // Carga las variables de entorno desde .env

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const { Pool } = require('pg'); // Cliente de PostgreSQL
const bcrypt = require('bcryptjs'); // Para el hashing seguro de contraseñas
const jwt = require('jsonwebtoken'); // Para generar y verificar tokens JWT
const cron = require('node-cron'); // Para programar tareas diarias
const mercadopago = require('mercadopago'); // SDK de Mercado Pago
const { DateTime } = require('luxon'); // Para manejo avanzado de fechas y zonas horarias

// --- CONFIGURACIÓN PRINCIPAL ---
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: { 
        origin: "baseUrl", // Permite conexiones desde cualquier origen (para desarrollo). ¡CAMBIAR EN PRODUCCIÓN!
        methods: ["GET", "POST"] 
    }
});
const baseUrl = process.env.RAILWAY_PUBLIC_URL || 'http://localhost:3000';

const PORT = process.env.PORT || 3000; // Puerto del servidor, Railway lo asignará a process.env.PORT

// --- CONFIGURACIÓN DE BASE DE DATOS PARA RAILWAY ---
// Railway proporciona una URL de conexión única para PostgreSQL a través de DATABASE_URL
const pool = new Pool({
    connectionString: process.env.DATABASE_URL, // Usa la DATABASE_URL de Railway
    ssl: {
        rejectUnauthorized: false // A menudo necesario en servicios en la nube como Railway
    }
});

// --- CONSTANTES Y CONFIGURACIÓN DE TERCEROS ---
const GAME_TIMES = ['20:00', '22:00'];
const MAX_PLAYERS_PER_GAME = 100;
const ENTRY_FEE = 1000.00; // Costo de entrada por partida

const mpClient = new mercadopago.MercadoPagoConfig({
    accessToken: process.env.MP_ACCESS_TOKEN, // Access Token de Mercado Pago (vendedor de prueba)
});

// --- MIDDLEWARES ---
app.use(cors()); // Habilita CORS
app.use(express.json()); // Habilita el parsing de JSON en las peticiones

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401); // No autorizado si no hay token

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403); // Prohibido si el token es inválido
        req.user = user; // Guarda el usuario decodificado en la request
        next();
    });
};

io.use((socket, next) => {
    const token = socket.handshake.auth?.token;
    if (!token) return next(new Error("Token no proporcionado"));

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        socket.user = decoded; // Adjunta la información del usuario al socket
        next();
    } catch (err) {
        next(new Error("Token inválido"));
    }
});


// --- FUNCIONES DE LÓGICA DE JUEGO ---
function generateBingoCard() {
    const columns = { 'B': [], 'I': [], 'N': [], 'G': [], 'O': [] };
    function fillColumn(start, end, count) {
        const numbers = Array.from({ length: end - start + 1 }, (_, i) => start + i);
        const selected = [];
        for (let i = 0; i < count; i++) {
            const randomIndex = Math.floor(Math.random() * numbers.length);
            selected.push(numbers.splice(randomIndex, 1)[0]);
        }
        return selected.sort((a, b) => a - b);
    }
    columns['B'] = fillColumn(1, 15, 5);
    columns['I'] = fillColumn(16, 30, 5);
    columns['N'] = fillColumn(31, 45, 5);
    columns['G'] = fillColumn(46, 60, 5);
    columns['O'] = fillColumn(61, 75, 5);
    columns['N'][2] = 0; // Casilla GRATIS
    const card = [];
    for (let row = 0; row < 5; row++) {
        card.push([columns['B'][row], columns['I'][row], columns['N'][row], columns['G'][row], columns['O'][row]]);
    }
    return card;
}

async function createDailyGames(dateInput) {
    const date = DateTime.fromJSDate(dateInput).setZone("America/Argentina/Buenos_Aires");
    console.log(`Creando partidas para: ${date.toLocaleString(DateTime.DATE_FULL)}`);
    for (const timeStr of GAME_TIMES) {
        const [hours, minutes] = timeStr.split(':').map(Number);
        let scheduledTime = date.set({ hour: hours, minute: minutes, second: 0, millisecond: 0 });
        const existingGame = await pool.query('SELECT id FROM games WHERE scheduled_time = $1', [scheduledTime.toJSDate()]);
        if (existingGame.rows.length === 0) {
            try {
                // El registro abre y cierra al mismo tiempo que la partida para simplificar, pero puedes cambiarlo.
                await pool.query(
                    `INSERT INTO games (scheduled_time, registration_open_at, registration_close_at, max_players, entry_fee, status)
                     VALUES ($1, $1, $1, $2, $3, $4)`,
                    [scheduledTime.toJSDate(), MAX_PLAYERS_PER_GAME, ENTRY_FEE, 'SCHEDULED']
                );
                console.log(`Partida creada: ${timeStr} para ${date.toISODate()}`);
            } catch (err) {
                console.error(`Error creando partida para ${timeStr}:`, err.message);
            }
        }
    }
}

const activeGames = {}; // Objeto para mantener el estado de los juegos en progreso

async function startGame(gameId) {
    if (activeGames[gameId]) {
        console.log(`Intento de iniciar la partida ${gameId}, que ya está en curso.`);
        return;
    }

    console.log(`--- INICIANDO PARTIDA ${gameId} ---`);

    try {
        await pool.query("UPDATE games SET status = 'IN_PROGRESS' WHERE id = $1", [gameId]);
        const numbersToCall = Array.from({ length: 75 }, (_, i) => i + 1);
        const calledNumbers = new Set();

        activeGames[gameId] = {
            intervalId: null,
            numbersToCall: numbersToCall,
            calledNumbers: calledNumbers,
        };
        
        io.to(String(gameId)).emit('gameStarted', { message: `¡La partida #${gameId} ha comenzado!` });

        activeGames[gameId].intervalId = setInterval(() => {
            const game = activeGames[gameId];

            if (game.numbersToCall.length === 0) {
                endGame(gameId, "Se han cantado todos los números.");
                return;
            }

            const randomIndex = Math.floor(Math.random() * game.numbersToCall.length);
            const newNumber = game.numbersToCall.splice(randomIndex, 1)[0];
            game.calledNumbers.add(newNumber);

            console.log(`Partida ${gameId}: Cantando número ${newNumber}`);
            io.to(String(gameId)).emit('newNumber', { number: newNumber, calledNumbers: Array.from(game.calledNumbers) });

        }, 5000); // 5 segundos
    } catch (error) {
        console.error(`Error al iniciar la partida ${gameId}:`, error);
    }
}

function endGame(gameId, reason) {
    if (!activeGames[gameId]) return;

    console.log(`--- TERMINANDO PARTIDA ${gameId}. Razón: ${reason} ---`);
    clearInterval(activeGames[gameId].intervalId);
    
    io.to(String(gameId)).emit('gameEnded', { message: `La partida ha terminado. ${reason}` });

    delete activeGames[gameId];

    pool.query("UPDATE games SET status = 'FINISHED' WHERE id = $1", [gameId])
        .catch(err => console.error(`Error actualizando estado de partida ${gameId} a FINISHED:`, err));
}


// --- RUTAS DE LA API ---
app.get('/', (req, res) => res.send('Servidor de Bingo Online funcionando!'));

app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).json({ message: 'Todos los campos son obligatorios.' });
    try {
        const existingUser = await pool.query('SELECT id FROM users WHERE username = $1 OR email = $2', [username, email]);
        if (existingUser.rows.length > 0) return res.status(409).json({ message: 'El nombre de usuario o el email ya están registrados.' });
        
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);
        const result = await pool.query(
            'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username, email',
            [username, email, passwordHash]
        );
        res.status(201).json({ message: 'Usuario registrado exitosamente!', user: result.rows[0] });
    } catch (error) {
        console.error('Error en registro:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});

app.post('/api/login', async (req, res) => {
    const { identifier, password } = req.body;
    if (!identifier || !password) return res.status(400).json({ message: 'Campos obligatorios.' });
    try {
        const userResult = await pool.query('SELECT * FROM users WHERE username = $1 OR email = $1', [identifier]);
        const user = userResult.rows[0];
        if (!user) return res.status(401).json({ message: 'Credenciales inválidas.' });

        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) return res.status(401).json({ message: 'Credenciales inválidas.' });

        const token = jwt.sign({ id: user.id, username: user.username, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ message: 'Inicio de sesión exitoso!', token, user: { id: user.id, username: user.username, email: user.email, balance: user.balance } });
    } catch (error) {
        console.error('Error en login:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});

app.get('/api/games', authenticateToken, async (req, res) => {
    
    try {
        const userId = req.user.id;
        const query = `
            SELECT 
                g.*,
                CASE WHEN p.user_id IS NOT NULL AND p.payment_status = 'APPROVED' THEN true ELSE false END AS is_user_registered
            FROM games g
            LEFT JOIN game_participants p ON g.id = p.game_id AND p.user_id = $1
            WHERE g.scheduled_time >= NOW() - interval '3 hours'
            ORDER BY g.scheduled_time ASC
        `;
        const gamesResult = await pool.query(query, [userId]);
        res.json(gamesResult.rows);
    } 
    catch (error) {
        console.error('Error al obtener partidas:', error);
        res.status(500).json({ message: 'Error interno.' });
    }
});

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
        const now = DateTime.now().setZone("America/Argentina/Buenos_Aires"); // Definir 'now' aquí
        if (now > DateTime.fromJSDate(game.registration_close_at).setZone("America/Argentina/Buenos_Aires")) throw new Error('El registro para esta partida ya ha cerrado.');
        if (game.current_players >= game.max_players) throw new Error('La partida está llena.');
        
        const existingRegistration = await clientDB.query('SELECT * FROM game_participants WHERE game_id = $1 AND user_id = $2', [gameId, userId]);
        if (existingRegistration.rows.length > 0) throw new Error('Ya estás registrado en esta partida.');

        const preferenceBody = {
            items: [{ title: `Inscripción a Bingo #${gameId}`, unit_price: parseFloat(game.entry_fee), quantity: 1, currency_id: "ARS" }],
            payer: { email: userEmail },
            external_reference: JSON.stringify({ gameId, userId }),
            back_urls: {
                success: `${process.env.RAILWAY_PUBLIC_URL}/api/payments/success`,
                failure: `${process.env.RAILWAY_PUBLIC_URL}/api/payments/failure`
            },
            notification_url: `${process.env.RAILWAY_PUBLIC_URL}/api/payments/webhook`,
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


// Webhook de Mercado Pago (Lógica robusta final)
app.post('/api/payments/webhook', async (req, res) => {
    console.log("--- INICIO DE WEBHOOK RECIBIDO ---");
    console.log("==> QUERY PARAMS:", JSON.stringify(req.query, null, 2));
    console.log("==> BODY:", JSON.stringify(req.body, null, 2));
    console.log("--- FIN DE WEBHOOK RECIBIDO ---");
    
    // Respondemos OK inmediatamente para que Mercado Pago no reintente.
    res.status(200).send('Webhook recibido y logueado.');
});

// Función auxiliar que ASUME la aprobación y procesa la orden
async function processOrderAsApproved(orderId) {
    try {
        const orderController = new mercadopago.MerchantOrder(mpClient);
        const order = await orderController.get({ merchantOrderId: orderId });

        // Si encontramos la orden y tiene nuestra referencia, procedemos.
        if (order && order.external_reference) {
            // Creamos un objeto de pago FALSO con los datos que necesitamos,
            // ya que no podemos fiarnos de la consulta al pago real.
            const fakeApprovedPayment = {
                id: order.payments?.[0]?.id || `sandbox-pmt-${orderId}`,
                status: 'approved'
            };
            // Llamamos a la función de lógica de negocio con el pago falso
            await processApprovedPayment(fakeApprovedPayment, order.external_reference);
        } else {
            console.error(`No se pudo encontrar la orden ${orderId} o no tenía external_reference.`);
        }
    } catch (error) {
        console.error(`Error procesando la orden ${orderId} de forma optimista:`, error);
    }
}

// Función auxiliar para actualizar la DB (esta se queda igual)
async function processApprovedPayment(payment, externalReference) {
    if (!externalReference) {
        console.error(`El pago ${payment.id} no tiene external_reference en la orden.`);
        return;
    }
        
    const { gameId, userId } = JSON.parse(externalReference);
    console.log(`Actualizando DB para gameId: ${gameId}, userId: ${userId}`);
    
    const clientDB = await pool.connect();
    try {
        await clientDB.query('BEGIN');
        const updateResult = await clientDB.query(
            `UPDATE game_participants SET payment_status = 'APPROVED', mp_payment_id = $1
             WHERE game_id = $2 AND user_id = $3 AND payment_status = 'PENDING' RETURNING id`,
            [payment.id, gameId, userId]
        );
        if (updateResult.rowCount > 0) {
            await clientDB.query(
                'UPDATE games SET current_players = current_players + 1 WHERE id = $1',
                [gameId]
            );
            console.log(`Usuario ${userId} confirmado en partida ${gameId}.`);
        } else {
            console.log(`El pago ${payment.id} ya fue procesado.`);
        }
        await clientDB.query('COMMIT');
    } catch (dbError) {
        await clientDB.query('ROLLBACK');
        console.error('Error de DB en webhook:', dbError);
    } finally {
        clientDB.release();
    }
}

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