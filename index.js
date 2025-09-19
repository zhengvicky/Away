const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { PrismaClient } = require("@prisma/client");
require("dotenv").config();

const prisma = new PrismaClient();
const app = express();
app.use(cors());
app.use(express.json());

// Middleware to authenticate token
const authenticate = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).send("Missing token");

  try {
    const token = authHeader.split(" ")[1];
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    res.status(401).send("Invalid token");
  }
};

app.post("/signup", async (req, res) => {
    const { email, password, name } = req.body;
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) return res.status(400).send("Email already registered");
  
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        name,
      },
    });
  
    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });
    res.send({ token, user: { id: user.id, email: user.email, name: user.name } });
  });

// Login
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).send("Invalid credentials");
  }
  const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET);
  res.send({ token });
});

// Create availability
app.post("/availability", authenticate, async (req, res) => {
  const { location, status, note, startDate, endDate, visibility } = req.body;
  const entry = await prisma.availability.create({
    data: {
      userId: req.user.userId,
      location,
      status,
      note,
      startDate: new Date(startDate),
      endDate: new Date(endDate),
      visibility,
    },
  });
  res.send(entry);
});

// Get own availability
app.get("/availability/me", authenticate, async (req, res) => {
  const entries = await prisma.availability.findMany({
    where: { userId: req.user.userId },
    orderBy: { startDate: "asc" },
  });
  res.send(entries);
});

app.listen(3000, () => console.log("Server running on http://localhost:3000"));
