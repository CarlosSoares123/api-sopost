const express = require('express')
const cookieParser = require('cookie-parser')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
const mysql = require('mysql2')
const cors = require('cors')
const multer = require('multer')
const bodyParser = require('body-parser')
const path = require('path')

const PORT = process.env.PORT || 9000

const app = express()
app.use(express.json())
app.use(cookieParser())

// Configuração do CORS
const corsOptions = {
  origin: function (origin, callback) {
    callback(null, true)
  },
  methods: ['POST', 'GET', 'DELETE', 'PUT'], // Métodos permitidos
  credentials: true, // Permitir envio de cookies
  allowedHeaders: ['Content-Type', 'Authorization'] // Cabeçalhos permitidos
}

app.use(cors(corsOptions))

// Configuração do body-parser
app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())

// Configuração do diretório de uploads como arquivos estáticos
app.use('/uploads', express.static(path.join(__dirname, 'uploads')))

// Configuração do Multer para upload de arquivos
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/') // Define o diretório onde os arquivos serão armazenados
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9)
    cb(null, uniqueSuffix + path.extname(file.originalname)) // Define o nome do arquivo no disco
  }
})

const upload = multer({ storage: storage }) // Configura o middleware Multer para lidar com o upload

// Conexão com o banco de dados
const db = mysql.createConnection({
  host: 'containers-us-west-178.railway.app',
  user: 'root',
  password: 'Fp8Jo49nNb2D3UrWqM99',
  database: 'railway',
  port: 7039,
  authPlugins: {
    mysql_clear_password: () => () => Buffer.from('\0' + 'Fp8Jo49nNb2D3UrWqM99')
  }
})

db.connect(err => {
  if (err) {
    console.log('Erro ao conectar com o banco de dados: ', err)
  } else {
    console.log('Conectado com o banco de dados ')
  }
})

process.on('SIGINT', () => {
  db.end()
  process.exit()
})

// Rota de login de usuário
app.post('/login', (req, res) => {
  const { email, password } = req.body

  // Verificar se o usuário existe no banco de dados
  const sql = 'SELECT * FROM users WHERE email = ?'

  db.query(sql, [email], (err, data) => {
    if (err) {
      console.log('Erro ao buscar o usuário:', err)
      return res.status(500).json({ error: 'Erro interno do servidor' })
    }
    // Validação se não houver usuário
    if (data.length === 0) {
      res.status(401).json({ message: 'Usuário inválido' })
      return
    }

    const userPassword = data[0].password
    const userId = data[0].id

    if (password) {
      // Verificar a senha
      bcrypt.compare(password, userPassword, (bcryptErr, bcryptResult) => {
        if (bcryptErr) {
          console.log('Erro ao comparar as senhas:', bcryptErr)
          return res.status(500).json({ error: 'Erro interno do servidor' })
        }

        if (bcryptResult) {
          // Senha correta, gerar token de autenticação
          const token = jwt.sign({ userId }, 'secret_key', { expiresIn: '1h' })

          // Enviar token como cookie
          res.cookie('token', token, { httpOnly: true })
          res.status(200).json({ message: 'Login bem-sucedido' })
        } else {
          // Senha incorreta
          res.status(401).json({ message: 'Senha incorreta' })
        }
      })
    } else {
      // Senha não fornecida
      res.status(400).json({ message: 'A senha não foi fornecida' })
    }
  })
})

// Rota de registro de usuário
app.post('/register', upload.single('image'), (req, res) => {
  const { name, email, password } = req.body
  const image = req.file.filename // Utiliza o novo nome gerado para a imagem

  // Verificar se o usuário já está registrado
  const checkUserSql = 'SELECT * FROM users WHERE email = ?'

  db.query(checkUserSql, [email], (err, data) => {
    if (err) {
      console.log('Erro ao verificar o usuário:', err)
      return res.status(500).json({ error: 'Erro interno do servidor' })
    }
    if (data.length > 0) {
      // Usuário já registrado
      res.status(409).json({ message: 'Usuário já registrado' })
    } else {
      // Registrar o usuário no banco de dados
      bcrypt.hash(password, 10, (hashErr, hashedPassword) => {
        if (hashErr) {
          console.log('Erro ao gerar o hash da senha:', hashErr)
          return res.status(500).json({ error: 'Erro interno do servidor' })
        }

        const insertUserSql =
          'INSERT INTO users (name, email, password, image) VALUES (?, ?, ?, ?)'

        db.query(
          insertUserSql,
          [name, email, hashedPassword, image],
          insertErr => {
            if (insertErr) {
              console.log('Erro ao inserir o usuário:', insertErr)
              return res.status(500).json({ error: 'Erro interno do servidor' })
            }
            res.status(201).json({ message: 'Usuário registrado com sucesso' })
          }
        )
      })
    }
  })
})

// Rota para obter informações do usuário
app.get('/user', (req, res) => {
  const token = req.cookies.token

  if (!token) {
    return res.status(401).json({ message: 'Não autenticado' })
  }

  try {
    const decodedToken = jwt.verify(token, 'secret_key')
    const userId = decodedToken.userId

    const sql = 'SELECT id, name, email, image FROM users WHERE id = ?'

    db.query(sql, [userId], (err, data) => {
      if (err) {
        console.log('Erro ao obter informações do usuário:', err)
        return res.status(500).json({ error: 'Erro interno do servidor' })
      }
      if (data.length === 0) {
        return res.status(404).json({ message: 'Usuário não encontrado' })
      }

      const user = {
        id: data[0].id,
        name: data[0].name,
        email: data[0].email,
        image: data[0].image
      }

      res.status(200).json({ user })
    })
  } catch (error) {
    return res.status(401).json({ message: 'Token inválido' })
  }
})

app.listen(PORT, () => {
  console.log(`Servidor iniciado na porta ${PORT}`)
})
