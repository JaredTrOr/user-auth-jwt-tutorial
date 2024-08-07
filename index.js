import express from 'express'
import jwt from 'jsonwebtoken'
import cookieParser from 'cookie-parser'
import { PORT, SECRET_JWT_KEY } from './config.js'
import { UserRepository } from './user-repository.js'

const app = express()

app.set('view engine', 'ejs')

app.use(express.json())
app.use(cookieParser())

// Middleware que verifica la cookie del usuario para ver si esta autenticado
app.use((req, res, next) => {
  const token = req.cookies.access_token
  req.session = { user: null }

  try {
    const data = jwt.verify(token, SECRET_JWT_KEY)
    req.session.user = data
  } catch { }
})

app.get('/', (req, res) => res.json('Hello world'))

app.post('/login', async (req, res) => {
  const { username, password } = req.body
  try {
    const user = await UserRepository.login({ username, password })

    const tokenPayload = {
      id: user._id,
      username: user.username
    }

    const tokenConfig = { expiresIn: '1h' }

    const token = jwt.sign(
      tokenPayload,
      SECRET_JWT_KEY,
      tokenConfig
    )

    res
      .cookie(
        'access_token',
        token,
        {
          httpOnly: true, // La cookie solo se puede acceder en el servidor
          secure: process.env.NODE_ENV === 'production', // La cookie solo se puede acceder con https (producción o no producción)
          sameSite: 'strict', // La cookie solo se puede acceder en el mismo dominio
          maxAge: 1000 * 60 * 60 // La cookie tiene tene tiempo de validez de una hora
        }
      )
      .json({ success: true, user, token })
  } catch (err) {
    res.status(401).json({ success: false, error: err.message })
  }
})

app.post('/register', async (req, res) => {
  const { username, password } = req.body

  try {
    const id = await UserRepository.create({ username, password })
    res.json({ success: true, id })
  } catch (err) {
    res.status(400).json({ success: false, error: err.message })
  }
})

app.post('/logout', (req, res) => {
  res
    .clearCookie('access_token')
    .json({ success: true, message: 'Logout succesful' })
})

app.get('/protected', (req, res) => {
  const { user } = req.session
  if (!user) return res.status(403).send('Access not authorized')
  res.render('protected', user)
})

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
})
