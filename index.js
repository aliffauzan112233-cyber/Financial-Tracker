import 'dotenv/config'
import { Hono } from 'hono'
import { serve } from '@hono/node-server'
import { serveStatic } from '@hono/node-server/serve-static'
import { setCookie, getCookie, deleteCookie } from 'hono/cookie'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

import { db } from './db/index.js'
import { users, transactions } from './db/schema.js'
import { eq } from 'drizzle-orm'

//  SETUP DASAR 
const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const app = new Hono()
const SECRET = process.env.JWT_SECRET || 'rahasia'

//  STATIC FILE 
app.use(
  '/public/*',
  serveStatic({ root: './' })
)

//  HELPER 
const loadHTML = async (folder, file) => {
  const filePath = path.join(__dirname, 'public', folder, file)
  return fs.promises.readFile(filePath, 'utf-8')
}

const auth = (c) => {
  const token = getCookie(c, 'token')
  if (!token) return null

  try {
    return jwt.verify(token, SECRET)
  } catch {
    return null
  }
}

//  ROUTING PAGE 
app.get('/', (c) => c.redirect('/login'))
app.get('/login', async (c) => c.html(await loadHTML('login', 'index.html')))
app.get('/register', async (c) => c.html(await loadHTML('register', 'index.html')))
app.get('/dashboard', async (c) => c.html(await loadHTML('dashboard', 'index.html')))

// AUTH API (untuk mendaftarkan akun) 
app.post('/api/register', async (c) => {
  const { username, password } = await c.req.json()

  const existing = await db
    .select()
    .from(users)
    .where(eq(users.username, username))

  if (existing.length > 0) {
    return c.json({ success: false, message: 'Username sudah dipakai' })
  }

  const hashedPassword = await bcrypt.hash(password, 10)

  await db.insert(users).values({
    username,
    password: hashedPassword
  })
return c.json({ success: true, message: 'Registrasi berhasil' })
})

//API/Login (untuk masuk)
app.post('/api/login', async (c) => {
  const { username, password } = await c.req.json()

  const found = await db
    .select()
    .from(users)
    .where(eq(users.username, username))

  if (found.length === 0) {
    return c.json({ success: false, message: 'Username atau password salah' })
  }

  const user = found[0]
  const validPassword = await bcrypt.compare(password, user.password)

  if (!validPassword) {
    return c.json({ success: false, message: 'Username atau password salah' })
  }

  const token = jwt.sign(
    { id: user.id, username: user.username },
    SECRET,
    { expiresIn: '1d' }
  )

  setCookie(c, 'token', token, {
    httpOnly: true,
    path: '/'
  })

  return c.json({ success: true, message: 'Login berhasil' })
})

//API/logout (untuk keluar)
app.post('/api/logout', (c) => {
  deleteCookie(c, 'token')
  return c.json({ success: true, message: 'Logout berhasil' })
})

// API/me (untuk mengecek apakah sudah login)
app.get('/api/me', (c) => {
  const user = auth(c)
  if (!user) return c.json({ success: false, message: 'Belum login' })
  return c.json({ success: true, user })
})

//MIDDLEWARE USER 
app.use('*', async (c, next) => {
  const user = auth(c)
  if (user) c.set('user', user)
  await next()
})

// TRANSACTION API 
app.get('/api/transactions', async (c) => {
  const user = c.get('user')
  if (!user) {
    return c.json({ success: false, message: 'Belum login' })
  }

  const data = await db
    .select()
    .from(transactions)
    .where(eq(transactions.userId, user.id))

  return c.json({ success: true, transactions: data })
})
//unutuk menambah transaksi
app.post('/api/transaction/add', async (c) => {
  try {
    const user = c.get('user')

    if (!user?.id) {
      return c.json(
        { success: false, message: 'User tidak valid' },
        401
      )
    }

    const { amount, date, status, description } = await c.req.json()

    if (!amount || !date || !status) {
      return c.json(
        { success: false, message: 'Data transaksi tidak lengkap' },
        400
      )
    }

    await db.insert(transactions).values({
      userId: user.id,
      nominal: Number(amount),
      transactionDate: new Date(date),
      status,
      description
    })

    return c.json({
      success: true,
      message: 'Transaksi berhasil ditambahkan'
    })
  } catch (error) {
    console.error('ADD TRANSACTION ERROR:', error)
    return c.json(
      { success: false, message: 'Terjadi kesalahan server' },
      500
    )
  }
})

//FALLBACK
app.notFound((c) => c.text('404 Not Found'))

//RUN SERVER (untuk menjalankan server)
serve({ fetch: app.fetch, port: 3001 }, () => {
  console.log('🚀 Server jalan di http://localhost:3001')
})
