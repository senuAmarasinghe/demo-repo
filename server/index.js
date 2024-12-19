import express from 'express';
import bodyParser from 'body-parser';
import mongoose from 'mongoose';
import cors from 'cors';
import dotenv from 'dotenv';
import multer from 'multer';
import helmet, { crossOriginResourcePolicy } from 'helmet';
import morgan from 'morgan';
import path from 'path';
import { fileURLToPath } from 'url';
/*import { register } from 'module';*/

import authRoutes from "./routes/auth.js";
import userRoutes from "./routes/users.js";
import postRoutes from "./routes/posts.js"; 
import { register } from "./controllers/auth.js";
import { createPost } from "./controllers/posts.js";
import { verifyToken } from './middleware/auth.js';
import User from "./models/User.js";
import Post from "./models/Post.js";
import { users, posts } from "./data/index.js";

/* CONFIGURATIONS */
const __filename  = fileURLToPath(import.meta.url);/*when using "type" : module,*/
const __dirname = path.dirname(__filename);

dotenv.config();
const app = express();
app.use(express.json());
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' } // Enable cross-origin resource policy
}));
app.use(morgan("common"));
app.use(bodyParser.json({ limit: "30mb", extended: true}));
app.use(cors({
  origin: 'http://localhost:3000', // Allow only this origin
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'], // Allowed HTTP methods
  credentials: true, // Allow credentials (e.g., cookies, authorization headers)
}));
app.use("/assets", express.static(path.join(__dirname, 'public/assets')));

/* FILE STORAGE */
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "public/assets");
  },
  filename: function (req, file, cb) {
    cb(null, file.originalname);
  }
});
const upload = multer({ storage });/*mongodb+srv://asenuthisahansa:zJY22NehDDNmWaHt@cluster0.4uloh.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0 */


/* ROUTES WITH FILES */
app.post("/auth/register", upload.single("picture"), register);
app.post("/posts", verifyToken, upload.single("picture"), createPost);

/* ROUTES */
app.use("/auth", authRoutes);
app.use("/users", userRoutes);
app.use("/posts", postRoutes);


/* MONGOOSE SETUP */
const PORT = process.env.PORT || 6001;

mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => {
      app.listen(PORT, () => console.log(`MongoDB Connected... server port : ${PORT}`));

      /* ADD DATA ONE TIME */
      //User.insertMany(users);
      //Post.insertMany(posts);
  }).catch((err) => console.log(`${err} did not connect`));