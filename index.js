require('dotenv').config();


const express = require('express');
const app = express();
const mongoose = require('mongoose');
const port = process.env.PORT || 5000;
const cors = require('cors');
const jwt = require("jsonwebtoken");
const SECRET_KEY = "yourSecretKey"; // secret key for jwt token
//monoDb connection
app.use(cors());
app.use(express.json());
const bcrypt = require("bcryptjs");

const connectDb = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log('MongoDB connected successfully');
  } catch (error) {
    console.log('Error connecting to the database:', error);
  }
};
connectDb();
const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String
})
 const User = mongoose.model('User',userSchema)

 const verifyToken = (req, res, next) => {
  const token = req.header("Authorization")?.split(" ")[1]; // Get token from header

  console.log(token);

  if (!token) return res.status(401).json({ message: "Access Denied" });

  try {
    const verified = jwt.verify(token, SECRET_KEY); // Verify token
    req.user = verified; // Attach user info to request
    next(); // Continue to the next middleware
  } catch (error) {
    res.status(400).json({ message: "Invalid Token" });
  }
};
app.post('/register',async (req,res)=>{
 const{name,email,password}= req.body
 const hashedPassword = await bcrypt.hash(password,10)
 const newUser = new User({name:name,email:email,password:hashedPassword})
 await newUser.save()
 res.json({ message: "User registered successfully!" });
})

// ✅ Login API
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  // Check if user exists
  const user = await User.findOne({ email });
  console.log(user)
  if (!user) {
    return res.status(400).json({ message: "User not found" });
  }

  // Compare hashed password
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(400).json({ message: "Invalid password" });
  }

  // Generate JWT Token
  const token = jwt.sign({ id: user._id }, SECRET_KEY, { expiresIn: "1h" });

  res.json({ message: "Login successful", token });
});

app.get("/users", async (req, res) => {
  try {
    const users = await User.find().select("-password"); // Exclude password for security
    res.json(users);
  } catch (error) {
    res.status(500).json({ message: "Error fetching users" });
  }
});


app.get("/profile", verifyToken, async (req, res) => {
  const user = await User.findById(req.user.id).select("-password"); // Exclude password
  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }
  res.json({ message: "Access granted!", user });
});



app.listen(port,()=>{
    console.log(`Server is running on port ${port}`);
})