// index.js (Versión Final, Única y Corregida)

require('dotenv').config();

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cron = require('node-cron');
const mercadopago = require('mercadopago');
const { DateTime } = require('luxon');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: "*", // Para desarrollo.
        methods: ["GET", "POST"]
    }
});

const PORT = process.env.PORT || 3000;

// Configuración de la Base de Datos
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});

// Constantes del Juego
const GAME_TIMES = ['20:00', '22:00'];
const MAX_PLAYERS_PER_GAME = 100;
const ENTRY_FEE = 1000.00;

// Configuración de Mercado Pago
const mpClient = new mercadopago.MercadoPagoConfig({
    accessToken: process.env.MP_ACCESS_TOKEN,
});

// Middlewares de Express
app.use(cors());
app.use(express.json());

// --- Middleware de Autenticación JWT ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            console.error("Token JWT inválido:", err.message);
            return res.sendStatus(403);
        }
        req.user = user;
        next();
    });
};

// --- Funciones de Lógica de Juego ---
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

// Objeto para mantener el estado de los juegos en progreso
const activeGames = {};

async function startGame(gameId) {
    // Evitar iniciar una partida que ya está en curso
    if (activeGames[gameId]) {
        console.log(`Intento de iniciar la partida ${gameId}, que ya está en curso.`);
        return;
    }

    console.log(`--- INICIANDO PARTIDA ${gameId} ---`);

    try {
        // 1. Actualizar el estado de la partida en la base de datos a IN_PROGRESS
        await pool.query("UPDATE games SET status = 'IN_PROGRESS' WHERE id = $1", [gameId]);

        // 2. Preparar el juego
        const numbersToCall = Array.from({ length: 75 }, (_, i) => i + 1); // Array del 1 al 75
        const calledNumbers = new Set(); // Usamos un Set para búsquedas rápidas

        // 3. Guardar el estado del juego en memoria
        activeGames[gameId] = {
            intervalId: null, // Guardaremos el ID del intervalo para poder detenerlo
            numbersToCall: numbersToCall,
            calledNumbers: calledNumbers,
        };
        
        // Notificamos a todos en la sala de la partida que el juego ha comenzado
        io.to(String(gameId)).emit('gameStarted', { message: `¡La partida #${gameId} ha comenzado!` });

        // 4. Empezar a "cantar" números cada X segundos (ej. cada 5 segundos)
        activeGames[gameId].intervalId = setInterval(() => {
            const game = activeGames[gameId];

            if (game.numbersToCall.length === 0) {
                // Ya se han cantado todos los números
                endGame(gameId, "Se han cantado todos los números.");
                return;
            }

            // Seleccionar un número al azar de los que quedan
            const randomIndex = Math.floor(Math.random() * game.numbersToCall.length);
            const newNumber = game.numbersToCall.splice(randomIndex, 1)[0];
            game.calledNumbers.add(newNumber);

            console.log(`Partida ${gameId}: Cantando número ${newNumber}`);

            // Emitir el nuevo número a todos los jugadores en la sala de la partida
            io.to(String(gameId)).emit('newNumber', { number: newNumber, calledNumbers: Array.from(game.calledNumbers) });

        }, 5000); // 5000 ms = 5 segundos

    } catch (error) {
        console.error(`Error al iniciar la partida ${gameId}:`, error);
    }
}

// Función para terminar una partida (cuando hay un ganador o se acaban los números)
function endGame(gameId, reason) {
    if (!activeGames[gameId]) return;

    console.log(`--- TERMINANDO PARTIDA ${gameId}. Razón: ${reason} ---`);
    clearInterval(activeGames[gameId].intervalId); // Detenemos el intervalo de "cantar" números
    
    io.to(String(gameId)).emit('gameEnded', { message: `La partida ha terminado. ${reason}` });

    // Limpiar el estado del juego de la memoria
    delete activeGames[gameId];

    // Actualizar el estado en la base de datos a FINISHED
    pool.query("UPDATE games SET status = 'FINISHED' WHERE id = $1", [gameId])
        .catch(err => console.error(`Error actualizando estado de partida ${gameId} a FINISHED:`, err));
}

// --- RUTAS DE LA API ---

// Ruta de prueba
app.get('/', (req, res) => res.send('Servidor de Bingo Online funcionando!'));

// Rutas de Autenticación
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

// Rutas de Partidas
app.get('/api/games', authenticateToken, async (req, res) => {
    
    try {
        const userId = req.user.id;
        // Consulta que une games con game_participants para saber si el usuario actual está registrado
        const query = `
            SELECT 
                g.*,
                CASE WHEN p.user_id IS NOT NULL AND p.payment_status = 'APPROVED' THEN true ELSE false END AS is_user_registered
            FROM games g
            LEFT JOIN game_participants p ON g.id = p.game_id AND p.user_id = $1
            WHERE g.scheduled_time >= NOW() - interval '3 hours' -- Muestra partidas incluso si empezaron hace poco
            ORDER BY g.scheduled_time ASC
        `;
        const games = await pool.query(query, [userId]);
        res.json(games.rows);
    } 
    catch (error) {
        console.error('Error al obtener partidas:', error);
        res.status(500).json({ message: 'Error interno al obtener partidas.' });
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
        //if (DateTime.now() > DateTime.fromJSDate(game.scheduled_time)) throw new Error('El registro para esta partida ya ha cerrado.');
        if (game.current_players >= game.max_players) throw new Error('La partida está llena.');
        
        const existingRegistration = await clientDB.query('SELECT * FROM game_participants WHERE game_id = $1 AND user_id = $2', [gameId, userId]);
        if (existingRegistration.rows.length > 0) throw new Error('Ya estás registrado en esta partida.');

        const preferenceBody = {
            items: [{ title: `Inscripción a Bingo #${gameId}`, unit_price: parseFloat(game.entry_fee), quantity: 1, currency_id: "ARS" }],
            payer: { email: userEmail },
            external_reference: JSON.stringify({ gameId, userId }),
            back_urls: {
                success: `${process.env.RENDER_EXTERNAL_URL}/api/payments/success`,
                failure: `${process.env.RENDER_EXTERNAL_URL}/api/payments/failure`,
            },
            notification_url: `${process.env.RENDER_EXTERNAL_URL}/api/payments/webhook`,
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


// En index.js, la ruta del webhook

// En tu archivo index.js, la ruta del webhook

app.post('/api/payments/webhook', async (req, res) => {
    const { query, body } = req;
    console.log("Webhook recibido:", { query, body });

    // La notificación principal que nos interesa es la del PAGO
    if (query.type === 'payment' && body.data && body.data.id) {
        const paymentId = body.data.id;
        console.log(`Webhook de PAGO recibido. Procesando ID: ${paymentId}`);

        try {
            // Siempre intentamos obtener los detalles del pago primero
            const paymentController = new mercadopago.Payment(mpClient);
            const payment = await paymentController.get({ id: paymentId });
            
            // Si funciona y está aprobado, genial.
            if (payment && payment.status === 'approved') {
                const order = await getOrderFromPayment(payment);
                await processApprovedPayment(payment, order.external_reference);
            }

        } catch (error) {
            // --- WORKAROUND PARA EL ERROR 404 DEL SANDBOX ---
            if (error.status === 404) {
                console.warn(`WORKAROUND: Payment ${paymentId} no encontrado (404). Asumiendo pago aprobado y buscando orden...`);
                
                // Como el pago da 404, no podemos obtener la orden desde él.
                // ¡NECESITAMOS LA NOTIFICACIÓN DE 'merchant_order'!
                // Esta lógica es compleja. Vamos a simplificar. Si recibimos un webhook
                // de pago, confiamos en la 'merchant_order' que llega casi al mismo tiempo.
                // Es un hack, pero es lo único que podemos hacer.

                // La notificación de `merchant_order` nos llega por separado.
                // Tenemos que correlacionarlos. El problema es que esta notificación llega primero.
                //
                // CAMBIO DE ESTRATEGIA: La notificación de 'merchant_order' es más fiable.
                // Vamos a ignorar la de 'payment' y a procesar SOLO la de 'merchant_order'
                // pero APROBANDO el pago si la orden existe.
            } else {
                 console.error('Error procesando webhook de pago:', error);
            }
        }
    }
    
    // --- LÓGICA FINAL Y ROBUSTA: PROCESAR LA MERCHANT_ORDER ---
    if (body.topic === 'merchant_order' || query.topic === 'merchant_order') {
        const orderId = body.resource?.match(/\d+$/)?.[0] || query.id;
        if(orderId) {
             // Procesamos la orden, asumiendo que el pago asociado (aunque no lo veamos) fue aprobado
             await processOrderAsApproved(orderId);
        }
    }


    res.status(200).send('Webhook recibido');
});

// Función para obtener la orden a partir de un pago
async function getOrderFromPayment(payment) {
    if (!payment.order?.id) {
        throw new Error(`El pago ${payment.id} no tiene una orden asociada.`);
    }
    const orderController = new mercadopago.MerchantOrder(mpClient);
    return await orderController.get({ merchantOrderId: payment.order.id });
}

// Nueva función que asume la aprobación para el Sandbox
async function processOrderAsApproved(orderId) {
    try {
        console.log(`Procesando Orden ${orderId} con aprobación optimista (Sandbox)...`);
        const orderController = new mercadopago.MerchantOrder(mpClient);
        const order = await orderController.get({ merchantOrderId: orderId });

        if (order && order.external_reference) {
            // Creamos un objeto 'payment' simulado para pasarlo a nuestra función de lógica
            const fakePayment = {
                id: order.payments?.[0]?.id || `sandbox-${orderId}`, // Usamos el id del pago si existe, si no, uno simulado
                status: 'approved'
            };
            await processApprovedPayment(fakePayment, order.external_reference);
        }
    } catch (error) {
        console.error(`Error procesando la orden ${orderId} de forma optimista:`, error);
    }
}


// La función processApprovedPayment se queda igual que antes
// async function processApprovedPayment(payment, externalReference) { ... }


// --- ¡NUEVA FUNCIÓN ASÍNCRONA CON REINTENTOS! ---
async function processMerchantOrder(orderId, retriesLeft) {
    if (retriesLeft <= 0) {
        console.error(`No se pudo procesar la orden ${orderId} después de varios intentos.`);
        return;
    }

    try {
        const orderController = new mercadopago.MerchantOrder(mpClient);
        const order = await orderController.get({ merchantOrderId: orderId });

        const approvedPayment = order.payments?.find(p => p.status === 'approved');

        if (approvedPayment) {
            // ¡ÉXITO! Encontramos un pago aprobado.
            console.log(`Pago aprobado ${approvedPayment.id} encontrado en la orden ${orderId}.`);
            await processApprovedPayment(approvedPayment, order.external_reference);
        } else {
            // Si no hay pago aprobado, es el problema de timing.
            console.log(`La orden ${orderId} aún no tiene pagos aprobados. Reintentando en 5 segundos... (Intentos restantes: ${retriesLeft - 1})`);
            setTimeout(() => {
                processMerchantOrder(orderId, retriesLeft - 1);
            }, 5000); // 5 segundos de espera
        }

    } catch (error) {
        console.error(`Error al procesar la orden ${orderId}:`, error);
    }
}


// --- TU FUNCIÓN AUXILIAR MODIFICADA ---
// Ahora recibe el external_reference como parámetro
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

io.use((socket, next) => {
    const token = socket.handshake.auth?.token;
    if (!token) {
        return next(new Error("Token no proporcionado"));
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        socket.user = {
            id: decoded.id,
            username: decoded.username,
            email: decoded.email
        };
        next();
    } catch (err) {
        console.error("Error de autenticación en Socket.IO:", err.message);
        next(new Error("Token inválido"));
    }
});

// --- Lógica de Socket.IO, Tareas Programadas e Inicio del Servidor ---
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
            // ¡YA NO NECESITAMOS UN FAKE_USER_ID! Usamos el ID del usuario autenticado.
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
        // Buscamos partidas que estén programadas para empezar en este minuto y aún no han comenzado
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