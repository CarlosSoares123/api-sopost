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
    cb(null, file.originalname) // Define o nome do arquivo no disco
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

// Rota de login de user
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
      bcrypt.compare(password, userPassword, (err, isMatch) => {
        if (err) {
          console.log('Erro ao comparar as senhas:', err)
          res.status(500).json({ error: 'Erro interno do servidor' })
          return
        }
        if (!isMatch) {
          res.status(401).json({ error: 'Senha Invalida' })
          return
        }
        // Gerar um token JWT
        const token = jwt.sign({ id: userId }, 'jsonwebtoken-carlos-soares')
        // Armazenar o token em um cookie
        res.cookie('token', token, {
          httpOnly: true,
          maxAge: 24 * 60 * 60 * 1000 // 24 horas
        })

        res.json('Usuario Logado')
      })
    } else {
      const { name, image } = data[0]
      res.json({ name, image })
    }
  })
})
// Rota para Logout
app.get('/logout', (req, res) => {
  // Rota GET para o endpoint "/logout" para realizar o logout do usuário
  res.clearCookie('token') // Limpa o cookie contendo o token de autenticação
  return res.json({ Status: 'Success' }) // Retorna uma resposta JSON indicando o status de sucesso
})
// Rota de Registro de user
app.post('/register', upload.single('image'), (req, res) => {
  const { email, name, surname, password } = req.body
  const image = req.file.filename // Obtém o nome do arquivo enviado através do upload

  const existName = 'SELECT * FROM users WHERE name = ?'
  db.query(existName, [name], async (err, data) => {
    if (err) {
      console.error('Erro ao executar a consulta: ', err)
      return res.status(500).json({ error: 'Erro interno do servidor' })
    }
    if (data.length > 0) {
      return res.status(409).json({ error: 'Nome de usuário já está em uso' })
    }

    const existEmail = 'SELECT * FROM users WHERE email = ?'
    db.query(existEmail, [email], (err, data) => {
      if (err) {
        console.error('Erro ao executar a consulta: ', err)
        return res.status(500).json({ error: 'Erro interno do servidor' })
      }
      if (data.length > 0) {
        return res.status(409).json({ error: 'Este Email já está em uso' })
      }

      // Hash da Senha
      bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
          console.log('Erro ao gerar o hash da senha: ', err)
          return res.status(500).json({ error: 'Erro interno do servidor' })
        }

        // Inserir usuário no banco de dados
        const insertUser =
          'INSERT INTO users (name, surname, email, image, password) VALUES (?, ?, ?, ?, ?)'
        db.query(
          insertUser,
          [name, surname, email, image, hashedPassword],
          (err, data) => {
            if (err) {
              console.log('Erro ao registrar o usuário: ', err)
              return res.status(500).json({ error: 'Erro interno do servidor' })
            }
            return res
              .status(201)
              .json({ message: 'Usuário registrado com sucesso' })
          }
        )
      })
    })
  })
})

app.get('/home', (req, res) => {
  // Verificar se o usuário está autenticado
  const token = req.cookies.token
  if (!token) {
    res.status(401).json({ message: 'Acesso não autorizado' })
    return
  }

  try {
    // Verificar a validade do token
    const decoded = jwt.verify(token, 'jsonwebtoken-carlos-soares')
    const userId = decoded.id

    // Obter os dados do usuário, incluindo a imagem, do banco de dados
    const sql = 'SELECT * FROM users WHERE id = ?'
    db.query(sql, [userId], (err, data) => {
      if (err) {
        console.log('Erro ao buscar o usuário:', err)
        return res.status(500).json({ error: 'Erro interno do servidor' })
      }

      // Verificar se o usuário existe
      if (data.length === 0) {
        res.status(404).json({ message: 'Usuário não encontrado' })
        return
      }

      const user = data[0]

      // Retornar os dados do usuário, incluindo a imagem
      res.json(user)
    })
  } catch (err) {
    console.log('Erro ao verificar o token:', err)
    res.status(401).json({ message: 'Acesso não autorizado' })
  }
})

//Middleware de autenticação
function authenticate(req, res, next) {
  const token = req.cookies.token

  if (!token) {
    res.status(401).json({ error: 'Acesso não autorizado' })
    return
  }

  //Verificar e decodificar o token JWT
  jwt.verify(token, 'jsonwebtoken-carlos-soares', (err, decoded) => {
    if (err) {
      console.log('Erro ao verificar o token: ', err)
      res.status(500).json({ error: 'Erro interno do servidor' })
      return
    }

    req.userId = decoded.id
    next()
  })
}

// Rota para criar um Postagem
app.post('/posts', authenticate, (req, res) => {
  const { text } = req.body
  const userId = req.userId

  //Inserir a postagem no banco de dados
  const sql = 'INSERT INTO posts (text, userId) VALUES ( ?, ?)'
  db.query(sql, [text, userId], (err, data) => {
    if (err) {
      console.log('Erro ao criar a postagem: ', err)
      res.status(500).json({ error: 'Erro interno do servidor' })
      return
    }

    res.status(201).json({ message: 'Postagem criada com sucesso' })
  })
})
// Rota para mostrar as Postagens
app.get('/posts', (req, res) => {
  // Buscar as postagens e informações do usuário do banco de dados
  const sql =
    'SELECT posts.id, posts.text, users.name, users.surname, users.email, users.image FROM posts JOIN users ON posts.userId = users.id'
  db.query(sql, (err, data) => {
    if (err) {
      console.log('Erro ao buscar as postagens:', err)
      res.status(500).json({ error: 'Erro interno do servidor' })
      return
    }

    res.json({ data })
  })
})

app.get('/', authenticate, (req, res) => {
  // Rota GET para a raiz do aplicativo, usando o middleware "verifyUser" para autenticação
  return res.json({ Status: 'Success', userId: req.UserId }) // Retorna uma resposta JSON com o status de sucesso e o nome do usuário autenticado
})

app.get('/posts_user', authenticate, (req, res) => {
  const userId = req.userId

  // Buscar as postagens do usuário com os dados do usuário relacionados
  const sql = `
    SELECT posts.*, users.name, users.surname, users.email, users.image
    FROM posts
    JOIN users ON posts.userId = users.id
    WHERE posts.userId = ?
  `
  db.query(sql, [userId], (err, data) => {
    if (err) {
      console.log('Erro ao buscar as postagens:', err)
      res.status(500).json({ error: 'Erro interno do servidor' })
      return
    }

    res.json({
      data
    })
  })
})

app.put('/posts/:id', authenticate, (req, res) => {
  const postId = req.params.id
  const { text } = req.body

  // Atualizar os dados do post no banco de dados
  const sql = 'UPDATE posts SET text = ? WHERE id = ?'
  db.query(sql, [text, postId], (err, data) => {
    if (err) {
      console.log('Erro ao atualizar os dados do post:', err)
      res.status(500).json({ error: 'Erro interno do servidor' })
      return
    }

    res.json({ message: 'Dados do post atualizados com sucesso' })
  })
})

app.delete('/posts/:id', authenticate, (req, res) => {
  const postId = req.params.id

  // Excluir o post do banc\o de dados
  const sql = 'DELETE FROM posts WHERE id = ?'
  db.query(sql, [postId], (err, data) => {
    if (err) {
      console.log('Erro ao excluir o post:', err)
      res.status(500).json({ error: 'Erro interno do servidor' })
      return
    }
    res.json({ message: 'Post excluído com sucesso' })
  })
})
// Inicialização do Servidor na Porta 8080
app.listen(PORT, () => {
  console.log(`Servidor Rodando na Porta ${PORT}`)
})