const express = require('express')
const users = require('../../controllers/users/users.js')
const router = express.Router()

router.get('/users/verify/:verificationToken', users.verifyUser)
router.post('/users/verify', users.verifyEmailSender)

module.exports = router

