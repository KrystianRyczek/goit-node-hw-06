const mongoose = require('mongoose')
const bCrypt = require('bcrypt')
const userSchema = new mongoose.Schema({
    userName: {
        type: String,},
    password: {
        type: String,
        required: [true, 'Password is required'],
      },
      email: {
        type: String,
        required: [true, 'Email is required'],
        unique: true,
      },
      subscription: {
        type: String,
        enum: ["starter", "pro", "business"],
        default: "starter"
      },
      token: {
        type: String,
        default: null,
      },
      avatarURL: {
        type: String,
        default: null,
      },
      verify: {
        type: Boolean,
        default: false,
      },
      verificationToken: {
        type: String,
        required: [true, 'Verify token is required'],
      },
},{
    versionKey: false,
    timestamps: true,
})


userSchema.methods.setPassword = async function (password) {
  this.password = await bCrypt.hash(password, 10)
}
 
userSchema.methods.validatePassword = async function (password) {
  return bCrypt.compare(password, this.password)
}
const Users = mongoose.model('user', userSchema, 'users')

module.exports = Users 