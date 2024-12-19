import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import User from "../models/User.js";

export const register = async (req, res) => {
    try {

        console.log("Request Body:", req.body);
        console.log("Uploaded File:", req.file);
        const { 
            firstName, 
            lastName, 
            email, 
            password, 
            picturePath, 
            friends, 
            location, 
            occupation 
        } = req.body;
        //for encrypt pwd
        const salt = await bcrypt.genSalt();//generate salt before hashing
        const passwordHash = await bcrypt.hash(password, salt);//combine pw with salt to produce a hashed password.

        const newUser = new User({
            firstName, 
            lastName, 
            email, 
            password: passwordHash, 
            picturePath, 
            friends, 
            location, 
            occupation,
            viewedProfile: Math.floor(Math.random() * 10000),
            impressions: Math.floor(Math.random() * 10000) 
        });
        const savedUser = await newUser.save();
        res.status(201).json(savedUser);
    } catch (error) {
        res.status(500).json({ error: error.message});
    }
};

/* LOGGING IN */
export const login = async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email: email });//search user with the provided email using user model.
        if (!user) return res.status(400).json({ msg: "User does not exist. "});

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ msg: "Invalid credentials. "});

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);//Uses the secret key stored in the JWT_SECRET environment variable to sign the token.
        delete user.password;//ensure the hashed password is not sent to the client for security reasons.
        res.status(200).json({ token, user });

    } catch (error) {
        res.status(500).json({ error: error.message});
    }
}