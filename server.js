require("dotenv").config();
const express = require("express");
const session = require("express-session");
const passport = require("passport");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const { google } = require("googleapis");
const mongoose = require("mongoose");
const MongoStore = require("connect-mongo");
const GoogleStrategy = require("passport-google-oauth20").Strategy;

const User = require("./models/User");
const authenticateJWT = require("./middlewares/auth");

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

console.log("Conectando a base: ", process.env.MONGO_URI)
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("Conectado ao MongoDB"))
  .catch((err) => console.error("Erro ao conectar ao MongoDB:", err));

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: process.env.MONGO_URI,
      collectionName: "sessions",
    }),
    cookie: { secure: false },
  })
);

// Inicializa o Passport e a sessão
app.use(passport.initialize());
app.use(passport.session());

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_REDIRECT_URI,
      scope: [
        "profile",
        "email",
        "https://www.googleapis.com/auth/calendar",
        "https://www.googleapis.com/auth/calendar.events"
      ],
      accessType: "offline", // Garante refresh_token
      prompt: "consent" // Força o Google a solicitar permissões novamente
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ googleId: profile.id });

        if (!user) {
          user = new User({
            googleId: profile.id,
            name: profile.displayName,
            email: profile.emails[0].value,
            profilePic: profile.photos[0].value,
          });
        }

        user.googleAccessToken = accessToken;
        user.googleRefreshToken = refreshToken; 
        const newAccessToken = jwt.sign(
          { id: user._id, name: user.name, email: user.email },
          process.env.JWT_SECRET,
          { expiresIn: "1h" }
        );

        const newRefreshToken = jwt.sign(
          { id: user._id },
          process.env.JWT_REFRESH_SECRET,
          { expiresIn: "14d" }
        );

        // Substituir refresh token antigo no banco
        user.refreshToken = newRefreshToken;
        await user.save();

        return done(null, { user, token: newAccessToken, refreshToken: newRefreshToken });
      } catch (err) {
        return done(err, null);
      }
    }
  )
);

// Serialização do usuário
passport.serializeUser((user, done) => {
  done(null, user);
});

// Desserialização do usuário
passport.deserializeUser((user, done) => {
  done(null, user);
});

// Rota de autenticação no Google
app.get(
  "/",
  (req, res, next) => { res.send("Tela Inicial"); return next(); }
);
// Rota de autenticação no Google
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get("/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/auth/failure" }),
  (req, res) => {
    res.json({
      message: "Autenticado com sucesso",
      token: req.user.token, // Access token (1h)
      refreshToken: req.user.refreshToken, // Refresh token (14d)
      user: req.user.user,
    });
  }
);

app.post("/refresh-token", async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(401).json({ message: "Token de atualização não fornecido" });
  }

  try {
    // Verificar se o refresh token é válido
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

    // Buscar usuário no banco e verificar o refresh token
    const user = await User.findOne({ _id: decoded.id });

    if (!user || user.refreshToken !== refreshToken) {
      return res.status(403).json({ message: "Refresh token inválido" });
    }

    // Gerar novos tokens
    const newAccessToken = jwt.sign(
      { id: user._id, name: user.name, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    const newRefreshToken = jwt.sign(
      { id: user._id },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: "14d" }
    );

    // Substituir o refresh token antigo no banco
    user.refreshToken = newRefreshToken;
    await user.save();

    res.json({
      token: newAccessToken,
      refreshToken: newRefreshToken,
    });
  } catch (err) {
    return res.status(403).json({ message: "Token inválido ou expirado" });
  }
});

// Rota de falha na autenticação
app.get("/auth/failure", (req, res) => {
  res.send("Falha na autenticação");
});

// Rota de perfil para verificar se o usuário está logado
app.get("/profile", authenticateJWT, (req, res) => {
  if (!req.user) {
    return res.status(401).json({ message: "Usuário não autenticado" });
  }
  res.json(req.user);
});

app.post("/logout", authenticateJWT, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);

    if (!user || !user.googleAccessToken) {
      return res.status(400).json({ message: "Usuário não autenticado no Google" });
    }

    // Revogar o token de acesso
    const revokeAccessTokenUrl = `https://oauth2.googleapis.com/revoke?token=${user.googleAccessToken}`;
    await axios.post(revokeAccessTokenUrl);

    // Revogar o refresh token (se existir)
    if (user.googleRefreshToken) {
      const revokeRefreshTokenUrl = `https://oauth2.googleapis.com/revoke?token=${user.googleRefreshToken}`;
      await axios.post(revokeRefreshTokenUrl);
    }

    // Remover os tokens do banco
    await User.findByIdAndUpdate(user._id, {
    refreshToken: null,     
      googleAccessToken: null,
      googleRefreshToken: null
    });

    res.json({ message: "Logout realizado com sucesso, sessão do Google encerrada" });

  } catch (err) {
    console.error("Erro ao revogar tokens do Google:", err);
    res.status(500).json({ message: "Erro ao realizar logout" });
  }
});


app.get("/calendar", authenticateJWT, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    
    if (!user || !user.googleAccessToken) {
      return res.status(401).json({ message: "Usuário não autenticado no Google Calendar" });
    }

    // Criar o cliente da API do Google Calendar
    const auth = new google.auth.OAuth2();
    auth.setCredentials({ access_token: user.googleAccessToken });

    const calendar = google.calendar({ version: "v3", auth });

    // Buscar os eventos do Google Calendar
    const response = await calendar.events.list({
      calendarId: "primary",
      timeMin: new Date().toISOString(),
      maxResults: 10,
      singleEvents: true,
      orderBy: "startTime",
    });

    res.json(response.data.items);
  } catch (error) {
    console.error("Erro ao buscar eventos do Google Calendar:", error);
    res.status(500).json({ message: "Erro ao buscar eventos da agenda" });
  }
});

app.post("/create-event", authenticateJWT, async (req, res) => {
  try {
    const { summary, description, startDateTime, endDateTime } = req.body;

    if (!summary || !startDateTime || !endDateTime) {
      return res.status(400).json({ message: "Campos obrigatórios: summary, startDateTime, endDateTime" });
    }

    const user = await User.findById(req.user.id);

    if (!user || !user.googleAccessToken) {
      return res.status(401).json({ message: "Usuário não autenticado no Google Calendar" });
    }

    // Criar o cliente da API do Google Calendar
    const auth = new google.auth.OAuth2();
    auth.setCredentials({ access_token: user.googleAccessToken });

    const calendar = google.calendar({ version: "v3", auth });

    // Criar o evento
    const event = {
      summary: summary,
      description: description || "",
      start: { dateTime: new Date(startDateTime).toISOString(), timeZone: "America/Sao_Paulo" },
      end: { dateTime: new Date(endDateTime).toISOString(), timeZone: "America/Sao_Paulo" },
    };

    const response = await calendar.events.insert({
      calendarId: "primary",
      resource: event,
    });

    res.json({ message: "Evento criado com sucesso!", event: response.data });
  } catch (error) {
    console.error("Erro ao criar evento no Google Calendar:", error);
    res.status(500).json({ message: "Erro ao criar evento na agenda" });
  }
});

// Inicia o servidor
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando em ${PORT}`);
});