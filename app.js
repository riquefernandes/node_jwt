require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

// config Json response

app.use(express.json());

// Models

const User = require("./models/User");

// Open route public

app.get("/", (req, res) => {
  res.status(200).json({ msg: "Bem vindo a nossa api" });
});

//register User

app.post("/auth/register", async (req, res) => {
  const { name, email, password, confirmPassword } = req.body;
  //validations
  if (!name) {
    return res.status(422).json({ msg: "O nome é obrigatório!" });
  }
  if (!email) {
    return res.status(422).json({ msg: "O mail é obrigatório!" });
  }
  if (!password) {
    return res.status(422).json({ msg: "a senha é obrigatória!" });
  }
  if (password !== confirmPassword) {
    return res
      .status(422)
      .json({ msg: "As senhas não confere, favor revise-a!" });
  }

  // check if the user is already registered

  const userExists = await User.findOne({ email: email });
  if (userExists) {
    return res.status(422).json({ msg: "Email já cadastrado!" });
  }
  //create password

  const salt = await bcrypt.genSalt(12);
  const passwordHash = await bcrypt.hash(password, salt);

  //create user

  const user = new User({
    name,
    email,
    password: passwordHash,
  });

  try {
    await user.save();
    res.status(201).json({ msg: "Usuário cadastrado com sucesso" });
  } catch (error) {
    console.log(error);
    res
      .status(500)
      .json({ msg: "Erro no servidor, tente novamente mais tarde!" });
  }
});

// Login User

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  //validações

  if (!email) {
    return res.status(422).json({ msg: "O mail é obrigatório!" });
  }
  if (!password) {
    return res.status(422).json({ msg: "a senha é obrigatória!" });
  }
  const user = await User.findOne({ email: email });
  if (!user) {
    return res.status(404).json({ msg: "Usuário não encontrado!" });
  }

  // check if password match

  const checkPassword = await bcrypt.compare(password, user.password);
  if (!checkPassword) {
    return res.status(422).json({ msg: "Senha inválida" });
  }
});

//credentials

const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASSWORD;

mongoose
  .connect(
    `mongodb+srv://${dbUser}:${dbPassword}@cluster0.ybvrjkr.mongodb.net/?retryWrites=true&w=majority`
  )
  .then(() => {
    app.listen(3000);
    console.log("Conected");
  })
  .catch((err) => {
    console.log(err);
  });

