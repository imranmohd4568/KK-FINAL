//file about creating api to register,login the user
import userModel from "../models/userModel.js";
import jwt from "jsonwebtoken"
import bcrypt from "bcrypt"
import validator from "validator"



//login user
const loginUser =async(req,res)=>{
    const {email,password}=req.body
    try{
        const user =await userModel.findOne({email})
        if(!user) return res.status(400).json({msg:"Invalid email or password"})

        const isMatch =await bcrypt.compare(password,user.password)
        if(!isMatch) return res.status(400).json({msg:"Invalid email or password"
            })
        const token = createToken(user._id);
        res.json({success:true,token})
        }
        catch(err){
                    console.error(err)
                    res.status(500).json({msg:"Server error"})
                }

    }



const createToken=(id)=>{
    return jwt.sign({id},process.env.JWT_SECRET)
}

//register user
const registerUser= async(req,res)=>{
    const {name,password,email}=req.body;
    try{
        //checking if user already exists
        const userExist=await userModel.findOne({email});
        if(userExist){
            return res.status(400).json({success:false,message:"user already exists"})
            }
            //validating mail format and strong password
            if(!validator.isEmail(email)){
                return res.status(400).json({success:false,message:"invalid email"})
                }
            if(password.length<8){
                return res.status(400).json({success:false,message:"please enter a strong password"})
                }
            //hashing password
                const salt= await bcrypt.genSalt(10)
                const hashedPassword=await bcrypt.hash(password,salt);
                //creating new user
                const newUser=await userModel.create({name,email,password:hashedPassword})
                //save
                const user= await newUser.save()
                //create token
                const token=createToken(user._id)
                //send token to user
                res.status(201).json({success:true,message:"user created",token});
    } catch (error){
        console.log(error);
        res.status(500).json({success:false,message:"error"})
    }
}


export {loginUser,registerUser};