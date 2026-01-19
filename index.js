import 'dotenv/config'
import { Hono } from 'hono'
import { serve } from '@hono/node-server'
import { setCookie, getCookie, deleteCookie } from 'hono/cookie'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

import { db } from './db/index.js'
import { users, transactions } from './db/schema.js'
import { eq } from 'drizzle-orm'

// setup folder dan server
const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const app = new Hono()
const SECRET = process.env.JWT_SECRET || 'rahasia'


// Fungsi untuk memuat HTML  

const loadHTML = async (folder, file) => {
  const filePath = path.join(__dirname, 'public', folder, file)
  return await fs.promises.readFile(filePath, 'utf-8')
}

// Routing halaman HTML 
app.get('/', (c) => c.redirect('/login'))
app.get('/login', async (c) => c.html(await loadHTML('login', 'index.html')))
app.get('/register', async (c) => c.html(await loadHTML('register', 'index.html')))
app.get('/dashboard', async (c) => c.html(await loadHTML('dashboard', 'index.html')))


// AUTH HELPERS (untuk mengecek apakah server sudah login dan mengambil token cokie dari browser)

function auth(c) {
  const token = getCookie(c, 'token')
  if (!token) return null

  try {
    return jwt.verify(token, SECRET)
  } catch {
    return null
  }
}


// Api REGISTER (jika belum punya akun)

app.post('/api/register', async (c) => {
  const { username, password } = await c.req.json()

  const existing = await db.select().from(users).where(eq(users.username, username))
  if (existing.length > 0) {
    return c.json({ success: false, message: 'Username sudah dipakai' })
  }

  const hashed = await bcrypt.hash(password, 10)

  await db.insert(users).values({
    username,
    password: hashed
  })

  // Retruns
  return c.json({ success: true, message: 'Registrasi berhasil' })
})


// LOGIN (ketika sudah mempunyai akun)

app.post('/api/login', async (c) => {
  const { username, password } = await c.req.json()

  const found = await db.select().from(users).where(eq(users.username, username))
  if (found.length === 0)
    return c.json({ success: false, message: 'Username atau password salah' })

  const user = found[0]

  // jika tidak ada maka akann gagal 
  const valid = await bcrypt.compare(password, user.password)
  if (!valid) return c.json({ success: false, message: 'Username atau password salah' })

    // jika password cocok maka akan di buatkan token 
  const token = jwt.sign(
    { id: user.id, username: user.username },
    SECRET,
    { expiresIn: '1d' }
  )
  // simpan token ke cokie (bukti bahwa user sudah login )
  setCookie(c, 'token', token, { httpOnly: true, path: '/' })

  return c.json({ success: true, message: 'Login berhasil' })
})


// LOGOUT (keluar)

app.post('/api/logout', (c) => {
  deleteCookie(c, 'token')
  return c.json({ success: true, message: 'Logout berhasil' })
})


// Api Me (untuk memastikan apakah sudah login atau belum)

app.get('/api/me', (c) => {
  const user = auth(c)
  if (!user) return c.json({ success: false, message: 'Belum login' })
  return c.json({ success: true, user })
})


// MIDDLEWARE: inject user

app.use("*", async (c, next) => {
  const user = auth(c)
  if (user) c.set("user", user)
  await next()
})


// GET Api TRANSACTIONS (Mengambil semua transaksi dari user yang sedang login.)

app.get("/api/transactions", async (c) => {
  const user = c.get("user")
  if (!user) return c.json({ success: false, message: "Belum login" })

  const rows = await db.select().from(transactions)
    .where(eq(transactions.userId, user.id))

  return c.json({ success: true, transactions: rows })
})


// Add/Tambah TRANSACTION 

app.post("/api/transaction/add", async (c) => {
  try {
    const user = c.get("user");
    console.log("USER:", user);

    if (!user || !user.id) {
      return c.json({
        success: false,
        message: "User tidak valid"
      }, 401);
    }

    const body = await c.req.json();
    const { amount, date, status, description } = body;

    if (!amount || !date || !status) {
      return c.json({
        success: false,
        message: "Data transaksi tidak lengkap"
      }, 400);
    }

    await db.insert(transactions).values({
      userId: user.id,
      nominal: Number(amount),
      transactionDate: new Date(date),
      status,
      description,
    });

    return c.json({
      success: true,
      message: "Transaksi berhasil ditambahkan"
    });
  } catch (err) {
    console.error("ADD TRANSACTION ERROR:", err);
    return c.json({
      success: false,
      message: "Terjadi kesalahan server"
    }, 500);
  }
});



app.notFound((c) => c.text('404 Not Found'))// users mengakses halaman yang tidak ada 

// jalankan server
serve({ fetch: app.fetch, port: 3001 }, () => {
  console.log('🚀 Server jalan di http://localhost:3001')
})
