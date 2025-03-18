const express = require("express");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const bcrypt = require('bcrypt');
const { z } = require('zod');

const { UserModel, TodoModel } = require("./db");

const app = express();

app.use(express.json());

mongoose.connect("todo-arnav");
const JWT_SECRET = "HOLA";


app.post("/signup", async function (req, res) {

    const requiredBody = z.object({
        email: z.string().min(3).max(100).email(),
        password: z.string.min(3).max(20),
        name: z.string().min(3).max(100)
    });

    const parseWithSuccess = requiredBody.safeParse(req.body);

    if(!parseWithSuccess.success) {
        res.json({
            message: "Incorrect Format",
            error: parseWithSuccess.error
        });
        return;
    }

    const email = req.body.email;
    const password = req.body.password;
    const name = req.body.name;
    let found = false;
    try {
        const hashedPass = bcrypt.hash(password, 10);
        await UserModel.create({
            email: email,
            password: (await hashedPass).toString(),
            name: name,
        });
    } catch (error) {
        found = true;
        res.status(400).json({
            message: "User already exists!",
        });
    }
    if(!found) {
        res.json({
            message: "You are signed up!",
        });
    }
});

app.post("/signin", async function (req, res) {
    const email = req.body.email;
    const password = req.body.password;

    const user = await UserModel.findOne({
        email: email,
    });

    if(!user) {
        res.status(403).json({
            message: "User does not exist in our database."
        });
        return;
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (passwordMatch) {
        const token = jwt.sign(
            {
                id: user._id.toString(),
            },
            JWT_SECRET
        );

        res.json({
            token: token,
            message: "You are signed in!",
        });
    } else {
        res.status(403).json({
            message: "Invalid Credentials!",
        });
    }
});

function auth(req, res, next) {
    const token = req.headers.token;
    const decodedData = jwt.verify(token, JWT_SECRET);
    if (decodedData) {
        req.userId = decodedData.id;
        next();
    } else {
        res.status(403).json({
            message: "Invalid Token!",
        });
    }
}

app.post("/todo", auth, async function (req, res) {
    const userId = req.userId;
    const title = req.body.title;
    const done = req.body.done;
    await TodoModel.create({
        userId,
        title,
        done,
    });
    res.json({
        message: "Todo created",
    });
});

app.get("/todos", auth, async function (req, res) {
    const userId = req.userId;
    const todos = await TodoModel.find({
        userId,
    });
    res.json({
        todos,
    });
});

app.listen(3000);