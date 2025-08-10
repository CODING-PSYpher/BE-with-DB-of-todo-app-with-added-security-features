const express = require("express");
const { UserModel, TodoModel } = require("./db");
const { auth, JWT_SECRET } = require("./auth");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const bcrypt = require('bcrypt');
const { z } = require("zod");

mongoose.connect("mongodb://localhost:27017/todo-app-but-secured")

const app = express();
app.use(express.json());

app.post("/signup", async function(req, res) {
    
    const requiredBody= z.object({
        email : z.string().email(),
        name: z.string().min(1).max(100),
        password:z.string().min(8).max(20)
    })
    const pasrsedDataWithSuccess= requiredBody.safeParse(req.body);
    
    if (!pasrsedDataWithSuccess.success) {
        res.json({
            message:"incorrect format",
            error: pasrsedDataWithSuccess.error
        })
    }
    
    
    const email = req.body.email;
    const name = req.body.name;
    const password = req.body.password;
    

    let errorThrown= false;
   try{
     const hashedPassword= await bcrypt.hash(password, 5);
    await UserModel.create({
        email: email,
        password: hashedPassword,
        name: name
    });
    
    
   }catch(error){
    return res.json({
        message:'User already exist'
    })
   }

   if(!errorThrown){
    return res.json({
        message: "You are signed up"
    })
   }

});


app.post("/signin", async function(req, res) {
    const email = req.body.email;
    const password = req.body.password;

    const response = await UserModel.findOne({
        email: email
    });

    if(!response){
        res.status(403).json({
            message:"user does not exist!"
        })
    }

    const passwordMatch = await bcrypt.compare(password, response.password);


    if (passwordMatch) {
        const token = jwt.sign({
            id: response._id.toString()
        }, JWT_SECRET);

        res.json({
            token
        })
    } else {
        res.status(403).json({
            message: "Incorrect credentials"
        })
    }
});


app.post("/todo", auth, async function(req, res) {
    const userId = req.userId;
    const title = req.body.title;
    const done = req.body.done;

    await TodoModel.create({
        userId,
        title,
        done
    });

    res.json({
        message: "Todo created"
    })
});


app.get("/todos", auth, async function(req, res) {
    const userId = req.userId;

    const todos = await TodoModel.find({
        userId
    });

    res.json({
        todos
    })
});

app.listen(3000);